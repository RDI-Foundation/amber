use super::*;

#[tokio::test]
async fn storage_resource_binding_stays_strong() {
    let dir = tmp_dir("storage-resource-binding-strong");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "test -d /var/lib/app && sleep 3600"],
            mounts: [
              { path: "/var/lib/app", from: "slots.state" },
            ],
            network: {
              endpoints: [{ name: "http", port: 8080 }],
            },
          },
          slots: {
            state: { kind: "storage" },
          },
          provides: {
            http: { kind: "http", endpoint: "http" },
          },
          exports: {
            http: "http",
          },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              resources: {{
                state: {{ kind: "storage" }}
              }},
              components: {{ child: "{child}" }},
              bindings: [
                {{ to: "#child.state", from: "resources.state" }}
              ]
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .expect("compile storage scenario");

    let scenario = &output.scenario;
    let child_id = scenario
        .components_iter()
        .find(|(_, c)| c.moniker.as_str() == "/child")
        .map(|(id, _)| id)
        .expect("child component");
    let binding = scenario
        .bindings
        .iter()
        .find(|b| b.to.component == child_id && b.to.name == "state")
        .expect("binding to child.state");

    assert!(
        !binding.weak,
        "storage bindings should remain strong when routed from a storage resource"
    );
    assert!(
        matches!(
            &binding.from,
            BindingFrom::Resource(resource)
                if resource.component == scenario.root && resource.name == "state"
        ),
        "expected resource binding from resources.state, got {:?}",
        binding.from
    );
}

#[tokio::test]
async fn program_can_mount_local_storage_resource_directly() {
    let dir = tmp_dir("storage-resource-direct-mount");
    let root_path = dir.path().join("root.json5");

    write_file(
        &root_path,
        r#"
        {
          manifest_version: "0.1.0",
          resources: {
            state: { kind: "storage" },
          },
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "test -d /var/lib/app && sleep 3600"],
            mounts: [
              { path: "/var/lib/app", from: "resources.state" },
            ],
            network: {
              endpoints: [{ name: "http", port: 8080 }],
            },
          },
          provides: {
            http: { kind: "http", endpoint: "http" },
          },
          exports: {
            http: "http",
          },
        }
        "#,
    );

    let output = default_compiler()
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .expect("compile storage scenario with direct resource mount");

    let root = output.scenario.component(output.scenario.root);
    assert!(
        root.resources.contains_key("state"),
        "root should retain the directly mounted storage resource"
    );
    assert!(
        root.program
            .as_ref()
            .expect("root program")
            .mounts()
            .iter()
            .any(|mount| matches!(
                mount,
                amber_scenario::ProgramMount::Resource { resource, .. } if resource == "state"
            )),
        "program should keep the direct resource mount"
    );
    assert!(
        output.scenario.bindings.is_empty(),
        "direct resource mounts should not require synthetic bindings"
    );
}

#[tokio::test]
async fn directly_mounted_storage_resource_fanout_is_rejected_at_link_time() {
    let dir = tmp_dir("direct-storage-resource-fanout");
    let root_path = dir.path().join("root.json5");

    write_file(
        &root_path,
        r#"
        {
          manifest_version: "0.1.0",
          resources: {
            state: { kind: "storage" },
          },
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "test -d /var/lib/a && test -d /var/lib/b && sleep 3600"],
            mounts: [
              { path: "/var/lib/a", from: "resources.state" },
              { path: "/var/lib/b", from: "resources.state" },
            ],
          },
        }
        "#,
    );

    let err = default_compiler()
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .expect_err("direct storage fanout should fail during linking");

    let crate::Error::Linker(crate::linker::Error::Multiple { errors, .. }) = err else {
        panic!("expected linker error, got {err}");
    };
    assert!(
        errors.iter().any(|error| matches!(
            error,
            crate::linker::Error::StorageResourceFanout { resource, .. } if resource == "state"
        )),
        "expected storage resource fanout linker error, got {errors:?}"
    );
}

#[tokio::test]
async fn mounted_storage_slot_requires_resource_binding_at_link_time() {
    let dir = tmp_dir("mounted-storage-slot-requires-resource-binding");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "test -d /var/lib/app && sleep 3600"],
            mounts: [
              { path: "/var/lib/app", from: "slots.state" },
            ],
            network: {
              endpoints: [{ name: "http", port: 8080 }],
            },
          },
          slots: {
            state: { kind: "storage" },
          },
          provides: {
            http: { kind: "http", endpoint: "http" },
          },
          exports: {
            http: "http",
          },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              components: {{ child: "{child}" }},
              exports: {{ http: "#child.http" }}
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let err = default_compiler()
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .expect_err("missing storage resource binding should fail during linking");

    let crate::Error::Linker(crate::linker::Error::Multiple { errors, .. }) = err else {
        panic!("expected linker error, got {err}");
    };
    assert!(
        errors.iter().any(|error| matches!(
            error,
            crate::linker::Error::StorageMountRequiresResource { slot, .. } if slot == "state"
        )),
        "expected storage mount linker error, got {errors:?}"
    );
    assert!(
        !errors
            .iter()
            .any(|error| matches!(error, crate::linker::Error::UnboundSlot { slot, .. } if slot == "state")),
        "mounted storage should report the storage-specific linker error instead of a generic unbound slot: {errors:?}"
    );
}

#[tokio::test]
async fn config_expanded_storage_mount_slot_requires_resource_binding_at_link_time() {
    let err = compile_single_child_fixture_error(
        "config-expanded-storage-slot-requires-resource-binding",
        r#"
        {
          manifest_version: "0.3.0",
          config_schema: {
            type: "object",
            properties: {
              mount_source: { type: "string" },
            },
            required: ["mount_source"],
          },
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "test -d /var/lib/app && sleep 3600"],
            mounts: [
              { path: "/var/lib/app", from: "${config.mount_source}" },
            ],
            network: {
              endpoints: [{ name: "http", port: 8080 }],
            },
          },
          slots: {
            state: { kind: "storage" },
          },
          provides: {
            http: { kind: "http", endpoint: "http" },
          },
          exports: {
            http: "http",
          },
        }
        "#,
        r#"
        mount_source: "slots.state"
        "#,
    )
    .await;

    let crate::Error::Linker(crate::linker::Error::Multiple { errors, .. }) = err else {
        panic!("expected linker error, got {err}");
    };
    assert!(
        errors.iter().any(|error| matches!(
            error,
            crate::linker::Error::StorageMountRequiresResource { slot, .. } if slot == "state"
        )),
        "expected storage mount linker error, got {errors:?}"
    );
    assert!(
        !errors
            .iter()
            .any(|error| matches!(error, crate::linker::Error::UnboundSlot { slot, .. } if slot == "state")),
        "config-expanded storage mount should not be reported as a generic unbound slot: {errors:?}"
    );
}

#[tokio::test]
async fn config_expanded_mount_unknown_slot_is_rejected_at_link_time() {
    let err = compile_single_child_fixture_error(
        "config-expanded-unknown-slot-mount",
        r#"
        {
          manifest_version: "0.3.0",
          config_schema: {
            type: "object",
            properties: {
              mount_source: { type: "string" },
            },
            required: ["mount_source"],
          },
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "sleep 3600"],
            mounts: [
              { path: "/var/lib/app", from: "${config.mount_source}" },
            ],
            network: {
              endpoints: [{ name: "http", port: 8080 }],
            },
          },
          provides: {
            http: { kind: "http", endpoint: "http" },
          },
          exports: {
            http: "http",
          },
        }
        "#,
        r#"
        mount_source: "slots.missing"
        "#,
    )
    .await;

    assert!(error_contains(
        &err,
        "mount source resolved to `slots.missing`"
    ));
    assert!(error_contains(&err, "no such slot exists on the component"));
}

#[tokio::test]
async fn config_expanded_mount_unknown_resource_is_rejected_at_link_time() {
    let err = compile_single_child_fixture_error(
        "config-expanded-unknown-resource-mount",
        r#"
        {
          manifest_version: "0.3.0",
          config_schema: {
            type: "object",
            properties: {
              mount_source: { type: "string" },
            },
            required: ["mount_source"],
          },
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "sleep 3600"],
            mounts: [
              { path: "/var/lib/app", from: "${config.mount_source}" },
            ],
            network: {
              endpoints: [{ name: "http", port: 8080 }],
            },
          },
          provides: {
            http: { kind: "http", endpoint: "http" },
          },
          exports: {
            http: "http",
          },
        }
        "#,
        r#"
        mount_source: "resources.state"
        "#,
    )
    .await;

    assert!(error_contains(
        &err,
        "mount source resolved to `resources.state`"
    ));
    assert!(error_contains(
        &err,
        "no such resource exists on the component"
    ));
}

#[tokio::test]
async fn config_expanded_framework_mount_requires_experimental_feature_at_link_time() {
    let err = compile_single_child_fixture_error(
        "config-expanded-framework-mount-feature",
        r#"
        {
          manifest_version: "0.3.0",
          config_schema: {
            type: "object",
            properties: {
              mount_source: { type: "string" },
            },
            required: ["mount_source"],
          },
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "sleep 3600"],
            mounts: [
              { path: "/var/run/docker.sock", from: "${config.mount_source}" },
            ],
            network: {
              endpoints: [{ name: "http", port: 8080 }],
            },
          },
          provides: {
            http: { kind: "http", endpoint: "http" },
          },
          exports: {
            http: "http",
          },
        }
        "#,
        r#"
        mount_source: "framework.docker"
        "#,
    )
    .await;

    assert!(error_contains(
        &err,
        "framework capability `framework.docker` requires experimental feature `docker`"
    ));
}

#[tokio::test]
async fn config_expanded_framework_mount_unknown_capability_is_rejected_at_link_time() {
    let err = compile_single_child_fixture_error(
        "config-expanded-framework-mount-unknown",
        r#"
        {
          manifest_version: "0.3.0",
          config_schema: {
            type: "object",
            properties: {
              mount_source: { type: "string" },
            },
            required: ["mount_source"],
          },
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "sleep 3600"],
            mounts: [
              { path: "/var/run/cap.sock", from: "${config.mount_source}" },
            ],
            network: {
              endpoints: [{ name: "http", port: 8080 }],
            },
          },
          provides: {
            http: { kind: "http", endpoint: "http" },
          },
          exports: {
            http: "http",
          },
        }
        "#,
        r#"
        mount_source: "framework.unknown"
        "#,
    )
    .await;

    assert!(error_contains(
        &err,
        "mount source resolved to unknown framework capability `framework.unknown`"
    ));
}

#[tokio::test]
async fn config_expanded_static_mount_paths_are_validated_at_link_time() {
    let err = compile_single_child_fixture_error(
        "config-expanded-static-mount-path-validation",
        r#"
        {
          manifest_version: "0.3.0",
          config_schema: {
            type: "object",
            properties: {
              mount_path: { type: "string" },
              mount_source: { type: "string" },
              value: { type: "string" },
            },
            required: ["mount_path", "mount_source", "value"],
          },
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "sleep 3600"],
            mounts: [
              { path: "${config.mount_path}", from: "${config.mount_source}" },
            ],
            network: {
              endpoints: [{ name: "http", port: 8080 }],
            },
          },
          provides: {
            http: { kind: "http", endpoint: "http" },
          },
          exports: {
            http: "http",
          },
        }
        "#,
        r#"
        mount_path: "relative/path",
        mount_source: "config.value",
        value: "hello"
        "#,
    )
    .await;

    assert!(error_contains(&err, "mount path must be absolute"), "{err}");
    assert!(error_contains(&err, "relative/path"), "{err}");
}

#[tokio::test]
async fn optional_mounted_storage_slot_is_rejected_at_link_time() {
    let dir = tmp_dir("optional-mounted-storage-slot");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "test -d /var/lib/app && sleep 3600"],
            mounts: [
              { path: "/var/lib/app", from: "slots.state" },
            ],
            network: {
              endpoints: [{ name: "http", port: 8080 }],
            },
          },
          slots: {
            state: { kind: "storage", optional: true },
          },
          provides: {
            http: { kind: "http", endpoint: "http" },
          },
          exports: {
            http: "http",
          },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              components: {{ child: "{child}" }},
              exports: {{ http: "#child.http" }}
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let err = default_compiler()
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .expect_err("optional mounted storage should fail during linking");

    let crate::Error::Linker(crate::linker::Error::Multiple { errors, .. }) = err else {
        panic!("expected linker error, got {err}");
    };
    assert!(
        errors.iter().any(|error| matches!(
            error,
            crate::linker::Error::StorageMountRequiresResource { slot, .. } if slot == "state"
        )),
        "expected optional storage mount linker error, got {errors:?}"
    );
}

#[tokio::test]
async fn mounted_storage_resource_fanout_is_rejected_at_link_time() {
    let dir = tmp_dir("mounted-storage-resource-fanout");
    let root_path = dir.path().join("root.json5");
    let first_child_path = dir.path().join("first.json5");
    let second_child_path = dir.path().join("second.json5");

    let child_manifest = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "test -d /var/lib/app && sleep 3600"],
            mounts: [
              { path: "/var/lib/app", from: "slots.state" },
            ],
          },
          slots: {
            state: { kind: "storage" },
          },
        }
        "#;
    write_file(&first_child_path, child_manifest);
    write_file(&second_child_path, child_manifest);
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              resources: {{
                state: {{ kind: "storage" }}
              }},
              components: {{
                first: "{first_child}",
                second: "{second_child}"
              }},
              bindings: [
                {{ to: "#first.state", from: "resources.state" }},
                {{ to: "#second.state", from: "resources.state" }}
              ]
            }}
            "##,
            first_child = file_url(&first_child_path),
            second_child = file_url(&second_child_path),
        ),
    );

    let err = default_compiler()
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .expect_err("mounted storage fanout should fail during linking");

    let crate::Error::Linker(crate::linker::Error::Multiple { errors, .. }) = err else {
        panic!("expected linker error, got {err}");
    };
    assert!(
        errors.iter().any(|error| matches!(
            error,
            crate::linker::Error::StorageResourceFanout { resource, .. } if resource == "state"
        )),
        "expected storage fanout linker error, got {errors:?}"
    );
}

#[tokio::test]
async fn storage_resource_params_resolve_from_component_config() {
    let dir = tmp_dir("storage-resource-param-config");
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
              storage_size: { type: "string" },
            },
            required: ["storage_size"],
          },
          resources: {
            state: {
              kind: "storage",
              params: { size: "${config.storage_size}" },
            },
          },
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
                child: {{
                  manifest: "{child}",
                  config: {{
                    storage_size: "12Gi"
                  }}
                }}
              }}
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let output = default_compiler()
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .expect("compile storage resource config scenario");

    let child = output
        .scenario
        .components_iter()
        .find(|(_, component)| component.moniker.as_str() == "/child")
        .map(|(_, component)| component)
        .expect("child component");
    assert_eq!(
        child
            .resources
            .get("state")
            .and_then(|resource| resource.params.size.as_deref()),
        Some("12Gi")
    );
}

#[tokio::test]
async fn storage_resource_params_reject_runtime_root_config() {
    let dir = tmp_dir("storage-resource-param-runtime-root");
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
              storage_size: { type: "string" },
            },
            required: ["storage_size"],
          },
          resources: {
            state: {
              kind: "storage",
              params: { size: "${config.storage_size}" },
            },
          },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              config_schema: {{
                type: "object",
                properties: {{
                  storage_size: {{ type: "string" }}
                }},
                required: ["storage_size"]
              }},
              components: {{
                child: {{
                  manifest: "{child}",
                  config: {{
                    storage_size: "${{config.storage_size}}"
                  }}
                }}
              }}
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let err = default_compiler()
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .expect_err("runtime root config in storage resource params should fail");

    assert!(
        error_contains(&err, "resources.state.params.size"),
        "expected resource param error, got {err}"
    );
    assert!(
        error_contains(&err, "not available at compile time"),
        "expected compile-time config resolution error, got {err}"
    );
}

#[tokio::test]
async fn storage_resource_params_resolve_from_forwarded_object_defaults() {
    let dir = tmp_dir("storage-resource-param-forwarded-object-default");
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
              storage: {
                type: "object",
                properties: {
                  size: { type: "string", default: "12Gi" },
                },
              },
            },
          },
          resources: {
            state: {
              kind: "storage",
              params: { size: "${config.storage.size}" },
            },
          },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              config_schema: {{
                type: "object",
                properties: {{
                  storage: {{
                    type: "object",
                    properties: {{}}
                  }}
                }}
              }},
              components: {{
                child: {{
                  manifest: "{child}",
                  config: {{
                    storage: "${{config.storage}}"
                  }}
                }}
              }}
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let output = default_compiler()
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .expect("compile storage resource config scenario");

    let child = output
        .scenario
        .components_iter()
        .find(|(_, component)| component.moniker.as_str() == "/child")
        .map(|(_, component)| component)
        .expect("child component");
    assert_eq!(
        child
            .resources
            .get("state")
            .and_then(|resource| resource.params.size.as_deref()),
        Some("12Gi")
    );
}

#[tokio::test]
async fn storage_resource_params_reject_forwarded_object_defaults_when_root_can_be_null() {
    let dir = tmp_dir("storage-resource-param-forwarded-object-nullable");
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
              storage: {
                type: "object",
                properties: {
                  size: { type: "string", default: "12Gi" },
                },
              },
            },
          },
          resources: {
            state: {
              kind: "storage",
              params: { size: "${config.storage.size}" },
            },
          },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              config_schema: {{
                type: "object",
                properties: {{
                  storage: {{
                    type: ["object", "null"],
                    properties: {{}}
                  }}
                }}
              }},
              components: {{
                child: {{
                  manifest: "{child}",
                  config: {{
                    storage: "${{config.storage}}"
                  }}
                }}
              }}
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let err = default_compiler()
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .expect_err("nullable runtime root config in storage resource params should fail");

    assert!(
        error_contains(&err, "resources.state.params.size"),
        "expected resource param error, got {err}"
    );
    assert!(
        error_contains(&err, "not available at compile time"),
        "expected compile-time config resolution error, got {err}"
    );
}

#[tokio::test]
async fn exporting_unbound_optional_slot_errors() {
    let dir = tmp_dir("scenario-export-unbound-slot");
    let root_path = dir.path().join("root.json5");

    write_file(
        &root_path,
        r#"
        {
          manifest_version: "0.1.0",
          slots: { api: { kind: "http", optional: true } },
          exports: { api: "api" },
        }
        "#,
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let err = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap_err();

    assert!(
        error_contains(&err, "external slot"),
        "expected external-slot export error, got {err}"
    );
}
