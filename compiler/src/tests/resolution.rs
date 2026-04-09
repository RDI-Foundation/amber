use super::*;

#[tokio::test]
async fn compile_twice_unpinned_fails_when_sources_removed() {
    let dir = tmp_dir("scenario-compile");
    let root_path = dir.path().join("root.json5");
    let a_path = dir.path().join("a.json5");
    let b_path = dir.path().join("b.json5");

    write_file(
        &a_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "a",
            entrypoint: ["a"],
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
          provides: { api: { kind: "http", endpoint: "endpoint" } },
          exports: { api: "api" },
        }
        "#,
    );

    write_file(
        &b_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "b",
            entrypoint: ["b"],
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
          provides: { llm: { kind: "llm", endpoint: "endpoint" } },
          exports: { llm: "llm" },
        }
        "#,
    );

    write_file(
        &root_path,
        &format!(
            r#"
            {{
              manifest_version: "0.1.0",
              components: {{
                a: "{a}",
                b: "{b}",
              }},
            }}
            "#,
            a = file_url(&a_path),
            b = file_url(&b_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);

    let compilation = compiler
        .compile(root_ref.clone(), standard_compile_options())
        .await
        .unwrap();

    assert_eq!(compilation.scenario.components.len(), 3);

    fs::remove_file(&root_path).unwrap();
    fs::remove_file(&a_path).unwrap();
    fs::remove_file(&b_path).unwrap();

    let err = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap_err();

    assert!(err.to_string().contains("io error"));
}

#[tokio::test]
async fn compile_twice_with_digest_pins_succeeds_when_sources_removed() {
    let dir = tmp_dir("scenario-compile-digest-pins");
    let root_path = dir.path().join("root.json5");
    let a_path = dir.path().join("a.json5");
    let b_path = dir.path().join("b.json5");

    let a_contents = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "a",
            entrypoint: ["a"],
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
          provides: { api: { kind: "http", endpoint: "endpoint" } },
          exports: { api: "api" },
        }
    "#;
    let b_contents = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "b",
            entrypoint: ["b"],
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
          provides: { llm: { kind: "llm", endpoint: "endpoint" } },
          exports: { llm: "llm" },
        }
    "#;

    write_file(&a_path, a_contents);
    write_file(&b_path, b_contents);

    let digest_a = a_contents.parse::<Manifest>().unwrap().digest();
    let digest_b = b_contents.parse::<Manifest>().unwrap().digest();

    let root_contents = format!(
        r#"
        {{
          manifest_version: "0.1.0",
          components: {{
            a: {{ url: "{a}", digest: "{da}" }},
            b: {{ url: "{b}", digest: "{db}" }},
          }},
        }}
        "#,
        a = file_url(&a_path),
        b = file_url(&b_path),
        da = digest_a,
        db = digest_b
    );
    write_file(&root_path, &root_contents);

    let root_digest = root_contents.parse::<Manifest>().unwrap().digest();
    let root_ref = ManifestRef::new(file_url(&root_path), Some(root_digest));

    let compiler = default_compiler();

    let compilation = compiler
        .compile(root_ref.clone(), standard_compile_options())
        .await
        .unwrap();

    assert_eq!(compilation.scenario.components.len(), 3);

    fs::remove_file(&root_path).unwrap();
    fs::remove_file(&a_path).unwrap();
    fs::remove_file(&b_path).unwrap();

    let compilation2 = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap();

    assert_eq!(compilation2.scenario.components.len(), 3);

    let order = graph::topo_order(&compilation2.scenario).unwrap();
    assert_eq!(order.len(), compilation2.scenario.components.len());
}

#[tokio::test]
async fn provenance_records_redirect_when_fetched() {
    let contents = r#"{ manifest_version: "0.1.0" }"#.to_string();
    let digest = contents.parse::<Manifest>().unwrap().digest();
    let (url, server) = spawn_redirecting_manifest_server(contents);

    let compiler = default_compiler();
    let root_ref = ManifestRef::new(url.clone(), Some(digest));

    let compilation = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap();

    let root_id = compilation.scenario.root;
    let prov = &compilation.provenance.components[root_id.0];
    assert_eq!(prov.declared_ref.url.as_url(), Some(&url));
    assert_eq!(prov.declared_ref.digest, Some(digest));
    assert_eq!(prov.observed_url.as_ref().map(|u| u.path()), Some("/final"));

    server.join().unwrap();
}

#[tokio::test]
async fn relative_manifest_refs_resolve_against_parent() {
    let dir = tmp_dir("scenario-relative-manifest-ref");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    write_file(&child_path, r#"{ manifest_version: "0.1.0" }"#);
    write_file(
        &root_path,
        r#"
        {
          manifest_version: "0.1.0",
          components: {
            child: "./child.json5"
          }
        }
        "#,
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);

    let compilation = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap();

    assert_eq!(compilation.scenario.components.len(), 2);

    let root_id = compilation.scenario.root;
    let root = compilation.scenario.components[root_id.0]
        .as_ref()
        .expect("root component should exist");
    let child_id = root
        .children
        .iter()
        .copied()
        .find(|id| {
            compilation.scenario.components[id.0]
                .as_ref()
                .expect("child should exist")
                .moniker
                .local_name()
                == Some("child")
        })
        .expect("child component");
    let prov = &compilation.provenance.components[child_id.0];
    assert_eq!(prov.declared_ref.url.as_str(), "./child.json5");
}

#[tokio::test]
async fn relative_manifest_refs_require_file_base() {
    let source: Arc<str> = r#"
        {
          manifest_version: "0.1.0",
          components: {
            child: "./child.json5"
          }
        }
        "#
    .into();
    let backend = Arc::new(StaticBackend::new(Arc::clone(&source)));
    let resolver = Resolver::new().with_remote(RemoteResolver::new(["test"], backend));
    let compiler = Compiler::new(resolver, DigestStore::default());
    let root_ref = ManifestRef::from_url("test://root".parse().unwrap());

    let err = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap_err();

    let crate::Error::Frontend(crate::frontend::Error::RelativeManifestRef { .. }) = err else {
        panic!("expected relative manifest ref error");
    };
}

#[tokio::test]
async fn missing_child_manifest_error_points_to_component_manifest_ref() {
    let dir = tmp_dir("missing-child-manifest");
    let root_path = dir.path().join("root.json5");

    write_file(
        &root_path,
        r#"
        {
          manifest_version: "0.2.0",
          components: {
            foo: "./does-not-exist.json",
          },
        }
        "#,
    );

    let compiler = default_compiler();
    let err = compiler
        .check(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .unwrap_err();

    let crate::Error::Frontend(crate::frontend::Error::ManifestRefResolution {
        child,
        reference,
        ..
    }) = err
    else {
        panic!("expected contextual child manifest resolution error");
    };
    assert_eq!(child.as_ref(), "foo");
    assert_eq!(reference.as_ref(), "./does-not-exist.json");
}

#[tokio::test]
async fn cycle_is_detected_across_url_aliases_with_same_digest() {
    let (url, server) = spawn_alias_cycle_manifest_server();

    let compiler = default_compiler();
    let root_ref = ManifestRef::from_url(url);

    let err = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap_err();

    assert!(err.to_string().contains("cycle"));

    server.join().unwrap();
}

#[tokio::test]
async fn delegated_export_requires_child_export() {
    let dir = tmp_dir("scenario-delegated-export-missing");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    write_file(&child_path, r#"{ manifest_version: "0.1.0" }"#);
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              components: {{
                child: "{child}",
              }},
              exports: {{ api: "#child.api" }},
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);

    let err = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap_err();

    assert!(error_contains(&err, "target references non-exported `api`"));
    assert!(error_contains(&err, "root component"));
}

#[tokio::test]
async fn binding_rejects_missing_child_slot() {
    let dir = tmp_dir("scenario-missing-child-slot");
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
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
          provides: { api: { kind: "http", endpoint: "endpoint" } },
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
                child: "{child}",
              }},
              program: {{
                image: "root",
                entrypoint: ["root"],
                network: {{ endpoints: [{{ name: "endpoint", port: 80 }}] }},
              }},
              provides: {{ api: {{ kind: "http", endpoint: "endpoint" }} }},
              bindings: [
                {{ to: "#child.missing", from: "provides.api" }},
              ],
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);

    let err = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap_err();

    assert!(error_contains(
        &err,
        "unknown slot `missing` on component /child"
    ));
}

#[tokio::test]
async fn binding_rejects_duplicate_target_for_singular_child_slot() {
    let dir = tmp_dir("scenario-duplicate-singular-binding");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");
    let provider_a_path = dir.path().join("provider-a.json5");
    let provider_b_path = dir.path().join("provider-b.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "child",
            entrypoint: ["child"],
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
          slots: { api: { kind: "http" } },
        }
        "#,
    );
    for provider_path in [&provider_a_path, &provider_b_path] {
        write_file(
            provider_path,
            r#"
            {
              manifest_version: "0.1.0",
              program: {
                image: "provider",
                entrypoint: ["provider"],
                network: { endpoints: [{ name: "api", port: 80 }] },
              },
              provides: { api: { kind: "http", endpoint: "api" } },
              exports: { api: "api" },
            }
            "#,
        );
    }
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              components: {{
                child: "{child}",
                provider_a: "{provider_a}",
                provider_b: "{provider_b}",
              }},
              bindings: [
                {{ to: "#child.api", from: "#provider_a.api" }},
                {{ to: "#child.api", from: "#provider_b.api" }},
              ],
            }}
            "##,
            child = file_url(&child_path),
            provider_a = file_url(&provider_a_path),
            provider_b = file_url(&provider_b_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);

    let err = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap_err();

    assert!(error_contains(&err, "bound more than once"));
}

#[tokio::test]
async fn resolve_tree_keeps_use_entries_out_of_component_tree() {
    let dir = tmp_dir("scenario-use-resolution");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");
    let wrapper_path = dir.path().join("wrapper.json5");

    write_file(&child_path, r#"{ manifest_version: "0.1.0" }"#);
    write_file(
        &wrapper_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "wrapper",
            entrypoint: ["wrapper"],
            network: { endpoints: [{ name: "api", port: 80 }] },
          },
          provides: { rewrite: { kind: "http", profile: "policy", endpoint: "api" } },
          exports: { rewrite: "rewrite" },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              experimental_features: ["policies"],
              use: {{
                wrapper: "{wrapper}",
              }},
              policies: ["#wrapper.rewrite"],
              components: {{
                child: "{child}",
              }},
            }}
            "##,
            wrapper = file_url(&wrapper_path),
            child = file_url(&child_path),
        ),
    );

    let compiler = default_compiler();
    let tree = compiler
        .resolve_tree(
            manifest_ref_for_path(&root_path),
            standard_compile_options().resolve,
        )
        .await
        .unwrap();

    assert!(tree.root.children.contains_key("child"));
    assert!(tree.root.uses.contains_key("wrapper"));

    let output = compiler
        .compile_from_tree(tree, standard_compile_options().optimize)
        .unwrap();
    assert_eq!(output.scenario.components.len(), 2);
}

#[tokio::test]
async fn used_manifest_must_not_require_root_slots() {
    let dir = tmp_dir("scenario-use-required-slot");
    let root_path = dir.path().join("root.json5");
    let wrapper_path = dir.path().join("wrapper.json5");

    write_file(
        &wrapper_path,
        r#"
        {
          manifest_version: "0.1.0",
          slots: { upstream: { kind: "http" } },
          program: {
            image: "wrapper",
            entrypoint: ["wrapper"],
            network: { endpoints: [{ name: "api", port: 80 }] },
          },
          provides: { rewrite: { kind: "http", profile: "policy", endpoint: "api" } },
          exports: { rewrite: "rewrite" },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              experimental_features: ["policies"],
              use: {{
                wrapper: "{wrapper}",
              }},
              policies: ["#wrapper.rewrite"],
            }}
            "##,
            wrapper = file_url(&wrapper_path),
        ),
    );

    let err = default_compiler()
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .unwrap_err();

    match err {
        crate::Error::Frontend(crate::frontend::Error::UseRequiresRootSlots {
            name,
            slots,
            ..
        }) => {
            assert_eq!(name.as_ref(), "wrapper");
            assert_eq!(slots.as_ref(), "upstream");
        }
        other => panic!("expected UseRequiresRootSlots error, got: {other}"),
    }
}

#[tokio::test]
async fn resolve_tree_resolves_policy_exports_from_use_entries() {
    let dir = tmp_dir("scenario-policy-resolve");
    let root_path = dir.path().join("root.json5");
    let wrapper_path = dir.path().join("wrapper.json5");

    write_file(
        &wrapper_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "wrapper",
            entrypoint: ["wrapper"],
            network: { endpoints: [{ name: "api", port: 80 }] },
          },
          provides: { rewrite: { kind: "http", profile: "policy", endpoint: "api" } },
          exports: { rewrite: "rewrite" },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              experimental_features: ["policies"],
              use: {{
                wrapper: "{wrapper}",
              }},
              policies: ["#wrapper.rewrite"],
            }}
            "##,
            wrapper = file_url(&wrapper_path),
        ),
    );

    let tree = default_compiler()
        .resolve_tree(
            manifest_ref_for_path(&root_path),
            standard_compile_options().resolve,
        )
        .await
        .unwrap();

    assert_eq!(tree.root.policies.len(), 1);
    assert_eq!(tree.root.policies[0].reference.alias, "wrapper");
    assert_eq!(tree.root.policies[0].reference.export, "rewrite");
    assert_eq!(
        tree.root.policies[0].capability.kind,
        amber_manifest::CapabilityKind::Http
    );
    assert_eq!(
        tree.root.policies[0].capability.profile.as_deref(),
        Some("policy")
    );
}

#[tokio::test]
async fn resolve_tree_follows_child_exports_for_policies() {
    let dir = tmp_dir("scenario-policy-child-export");
    let root_path = dir.path().join("root.json5");
    let wrapper_path = dir.path().join("wrapper.json5");
    let leaf_path = dir.path().join("leaf.json5");

    write_file(
        &leaf_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "leaf",
            entrypoint: ["leaf"],
            network: { endpoints: [{ name: "api", port: 80 }] },
          },
          provides: { rewrite: { kind: "http", profile: "policy", endpoint: "api" } },
          exports: { rewrite: "rewrite" },
        }
        "#,
    );
    write_file(
        &wrapper_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              components: {{
                leaf: "{leaf}",
              }},
              exports: {{ rewrite: "#leaf.rewrite" }},
            }}
            "##,
            leaf = file_url(&leaf_path),
        ),
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              experimental_features: ["policies"],
              use: {{
                wrapper: "{wrapper}",
              }},
              policies: ["#wrapper.rewrite"],
            }}
            "##,
            wrapper = file_url(&wrapper_path),
        ),
    );

    let tree = default_compiler()
        .resolve_tree(
            manifest_ref_for_path(&root_path),
            standard_compile_options().resolve,
        )
        .await
        .unwrap();

    assert_eq!(tree.root.policies.len(), 1);
    assert_eq!(
        tree.root.policies[0].capability.kind,
        amber_manifest::CapabilityKind::Http
    );
    assert_eq!(
        tree.root.policies[0].capability.profile.as_deref(),
        Some("policy")
    );
}

#[tokio::test]
async fn policy_ref_requires_resolvable_export() {
    let dir = tmp_dir("scenario-policy-missing-export");
    let root_path = dir.path().join("root.json5");
    let wrapper_path = dir.path().join("wrapper.json5");

    write_file(&wrapper_path, r#"{ manifest_version: "0.1.0" }"#);
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              experimental_features: ["policies"],
              use: {{
                wrapper: "{wrapper}",
              }},
              policies: ["#wrapper.rewrite"],
            }}
            "##,
            wrapper = file_url(&wrapper_path),
        ),
    );

    let err = default_compiler()
        .resolve_tree(
            manifest_ref_for_path(&root_path),
            standard_compile_options().resolve,
        )
        .await
        .unwrap_err();

    match err {
        crate::Error::Frontend(crate::frontend::Error::PolicyExportUnresolved {
            policy,
            use_name,
            export,
            ..
        }) => {
            assert_eq!(policy.as_ref(), "#wrapper.rewrite");
            assert_eq!(use_name.as_ref(), "wrapper");
            assert_eq!(export.as_ref(), "rewrite");
        }
        other => panic!("expected PolicyExportUnresolved error, got: {other}"),
    }
}

#[tokio::test]
async fn policy_ref_requires_http_policy_provide() {
    let dir = tmp_dir("scenario-policy-invalid-capability");
    let root_path = dir.path().join("root.json5");
    let wrapper_path = dir.path().join("wrapper.json5");

    write_file(
        &wrapper_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "wrapper",
            entrypoint: ["wrapper"],
            network: { endpoints: [{ name: "api", port: 80 }] },
          },
          provides: { rewrite: { kind: "http", endpoint: "api" } },
          exports: { rewrite: "rewrite" },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              experimental_features: ["policies"],
              use: {{
                wrapper: "{wrapper}",
              }},
              policies: ["#wrapper.rewrite"],
            }}
            "##,
            wrapper = file_url(&wrapper_path),
        ),
    );

    let err = default_compiler()
        .resolve_tree(
            manifest_ref_for_path(&root_path),
            standard_compile_options().resolve,
        )
        .await
        .unwrap_err();

    match err {
        crate::Error::Frontend(crate::frontend::Error::InvalidPolicyExport {
            policy,
            message,
            ..
        }) => {
            assert_eq!(policy.as_ref(), "#wrapper.rewrite");
            assert_eq!(
                message.as_ref(),
                "must resolve to an `http` provide with profile `policy`, got `http`"
            );
        }
        other => panic!("expected InvalidPolicyExport error, got: {other}"),
    }
}

#[tokio::test]
async fn policy_ref_rejects_slot_exports() {
    let dir = tmp_dir("scenario-policy-slot-export");
    let root_path = dir.path().join("root.json5");
    let wrapper_path = dir.path().join("wrapper.json5");

    write_file(
        &wrapper_path,
        r#"
        {
          manifest_version: "0.1.0",
          slots: { rewrite: { kind: "http", profile: "policy", optional: true } },
          exports: { rewrite: "rewrite" },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              experimental_features: ["policies"],
              use: {{
                wrapper: "{wrapper}",
              }},
              policies: ["#wrapper.rewrite"],
            }}
            "##,
            wrapper = file_url(&wrapper_path),
        ),
    );

    let err = default_compiler()
        .resolve_tree(
            manifest_ref_for_path(&root_path),
            standard_compile_options().resolve,
        )
        .await
        .unwrap_err();

    match err {
        crate::Error::Frontend(crate::frontend::Error::InvalidPolicyExport {
            policy,
            message,
            ..
        }) => {
            assert_eq!(policy.as_ref(), "#wrapper.rewrite");
            assert_eq!(message.as_ref(), "must resolve to a provide, not a slot");
        }
        other => panic!("expected InvalidPolicyExport error, got: {other}"),
    }
}
