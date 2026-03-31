use super::*;

#[test]
fn components_sugar_parses() {
    let m: Manifest = r##"
        {
          manifest_version: "0.1.0",
          components: {
            a: "https://example.com/amber/pkg/v1",
            b: { manifest: "https://example.com/amber/other", config: { k: 1 } },
          }
        }
        "##
    .parse()
    .unwrap();

    match m.components.get("a").unwrap() {
        ComponentDecl::Reference(r) => {
            assert_eq!(r.url.as_str(), "https://example.com/amber/pkg/v1");
            assert!(r.digest.is_none());
        }
        _ => panic!("expected reference"),
    }

    match m.components.get("b").unwrap() {
        ComponentDecl::Object(i) => {
            assert_eq!(i.manifest.url.as_str(), "https://example.com/amber/other");
            assert!(i.manifest.digest.is_none());
            assert_eq!(i.config.as_ref().unwrap()["k"], 1);
        }
        _ => panic!("expected object reference"),
    }
}

#[test]
fn relative_manifest_ref_parses() {
    let m: Manifest = r##"
        {
          manifest_version: "0.1.0",
          components: {
            child: "./child.json5",
          }
        }
        "##
    .parse()
    .unwrap();

    match m.components.get("child").unwrap() {
        ComponentDecl::Reference(r) => {
            assert!(r.url.is_relative());
            assert_eq!(r.url.as_str(), "./child.json5");
        }
        _ => panic!("expected reference"),
    }
}

#[test]
fn component_object_environment_parses() {
    let m: Manifest = r##"
        {
          manifest_version: "0.1.0",
          environments: {
            env: { resolvers: ["r1"] },
          },
          components: {
            child: { manifest: "https://example.com/child", environment: "env" },
          }
        }
        "##
    .parse()
    .unwrap();

    let ComponentDecl::Object(obj) = m.components.get("child").unwrap() else {
        panic!("expected object component decl");
    };
    assert_eq!(obj.manifest.url.as_str(), "https://example.com/child");
    assert_eq!(obj.environment.as_deref(), Some("env"));
}

#[test]
fn environment_reference_must_exist() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          components: {
            child: { manifest: "https://example.com/child", environment: "missing" },
          },
          environments: {
            present: { resolvers: ["x"] },
          },
        }
        "#,
    );
    let err = raw.validate().unwrap_err();
    match err {
        Error::UnknownComponentEnvironment { child, environment } => {
            assert_eq!(child, "child");
            assert_eq!(environment, "missing");
        }
        other => panic!("expected UnknownComponentEnvironment error, got: {other}"),
    }
}

#[test]
fn environment_extends_cycle_is_rejected() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          environments: {
            a: { extends: "b", resolvers: ["x"] },
            b: { extends: "a", resolvers: ["y"] },
          },
        }
        "#,
    );
    let err = raw.validate().unwrap_err();
    assert!(matches!(err, Error::EnvironmentCycle { .. }));
}

#[test]
fn environment_extends_unknown_is_rejected() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          environments: {
            a: { extends: "missing", resolvers: ["x"] },
          },
        }
        "#,
    );
    let err = raw.validate().unwrap_err();
    match err {
        Error::UnknownEnvironmentExtends { name, extends } => {
            assert_eq!(name, "a");
            assert_eq!(extends, "missing");
        }
        other => panic!("expected UnknownEnvironmentExtends error, got: {other}"),
    }
}

#[test]
fn manifest_ref_canonical_form_with_digest_parses() {
    let m: Manifest = r##"
        {
          manifest_version: "0.1.0",
          components: {
            a: {
              url: "https://example.com/amber/pkg/v1",
              digest: "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            }
          }
        }
        "##
    .parse()
    .unwrap();

    match m.components.get("a").unwrap() {
        ComponentDecl::Reference(r) => {
            assert_eq!(r.url.as_str(), "https://example.com/amber/pkg/v1");
            let digest = r.digest.as_ref().unwrap();
            assert_eq!(digest.bytes(), &[0u8; 32]);
        }
        _ => panic!("expected reference"),
    }
}

#[test]
fn manifest_ref_invalid_digest_errors() {
    let err = r##"
        {
          manifest_version: "0.1.0",
          components: {
            a: { url: "https://example.com/amber/pkg/v1", digest: "sha256:not_base64" }
          }
        }
        "##
    .parse::<Manifest>()
    .unwrap_err();

    let message = err.to_string();
    assert!(
        message.contains("invalid manifest digest"),
        "expected digest error, got: {message}"
    );
}

#[test]
fn manifest_ref_unknown_field_errors() {
    let err = r##"
        {
          manifest_version: "0.1.0",
          components: {
            a: {
              url: "https://example.com/amber/pkg/v1",
              digest: "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
              extra: "nope",
            }
          }
        }
        "##
    .parse::<Manifest>()
    .unwrap_err();

    let message = err.to_string();
    assert!(
        message.contains("unknown field") && message.contains("extra"),
        "expected unknown field error, got: {message}"
    );
}

#[test]
fn manifest_digest_is_stable_across_json5_formatting() {
    let manifest_a = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
          provides: { api: { kind: "http", endpoint: "endpoint" } },
          exports: { api: "api" },
        }
        "#
    .parse::<Manifest>()
    .unwrap();

    let manifest_b = r#"
        {
          exports: {
            api: "api",
          },
          provides: {
            api: { kind: "http", endpoint: "endpoint" },
          },
          program: {
            image: "x",
            entrypoint: ["x"],
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
          manifest_version: "0.1.0",
        }
        "#
    .parse::<Manifest>()
    .unwrap();

    let digest_a = manifest_a.digest();
    let digest_b = manifest_b.digest();
    assert_eq!(digest_a, digest_b);
}

#[test]
fn endpoint_validation_fails_for_unknown_reference() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            network: { endpoints: [ { name: "endpoint", port: 80 } ] }
          },
          provides: {
            api: { kind: "http", endpoint: "missing" }
          },
          exports: { api: "api" },
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    assert!(err.to_string().contains("unknown endpoint `missing`"));
}

#[test]
fn endpoint_validation_fails_for_missing_provide_endpoint() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            network: { endpoints: [ { name: "endpoint", port: 80 } ] }
          },
          provides: {
            api: { kind: "http" }
          },
          exports: { api: "api" },
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    assert!(
        err.to_string()
            .contains("provide `api` must declare an endpoint")
    );
}

#[test]
fn duplicate_endpoint_names_error() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            network: {
              endpoints: [
                { name: "endpoint", port: 80 },
                { name: "endpoint", port: 81 },
              ]
            }
          }
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    assert!(
        err.to_string()
            .contains("duplicate endpoint name `endpoint`")
    );
}

#[test]
fn endpoint_validation_passes_for_defined_reference() {
    let m: Manifest = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            network: { endpoints: [ { name: "endpoint", port: 80 } ] }
          },
          provides: {
            api: { kind: "http", endpoint: "endpoint" }
          },
          exports: { api: "api" },
        }
        "#
    .parse()
    .unwrap();

    let program = m.program.as_ref().expect("program");
    assert_eq!(program.image_ref(), Some("x"));

    let network = program.network().expect("network");
    assert_eq!(network.endpoints().len(), 1);
    let endpoint = network.endpoints().iter().find(|endpoint| {
        endpoint.literal_name() == Some("endpoint")
            && endpoint.literal_port() == Some(80)
            && endpoint.literal_protocol() == Some(NetworkProtocol::Http)
    });
    assert!(endpoint.is_some(), "expected concrete endpoint");

    let api = m.provides.get("api").expect("api provide");
    assert_eq!(api.decl.kind, CapabilityKind::Http);
    assert_eq!(api.endpoint.as_deref(), Some("endpoint"));
    assert!(m.exports.contains_key("api"));
}

#[test]
fn endpoint_validation_still_rejects_unknown_provide_with_conditional_literal_endpoints() {
    let err = r#"
        {
          manifest_version: "0.3.0",
          config_schema: {
            type: "object",
            properties: {
              enabled: { type: "boolean" },
            },
          },
          program: {
            image: "x",
            entrypoint: ["x"],
            network: {
              endpoints: [
                { name: "api", port: 80 },
                { when: "config.enabled", name: "admin", port: 81 },
              ]
            }
          },
          provides: {
            api: { kind: "http", endpoint: "missing" }
          },
          exports: { api: "api" },
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    assert!(err.to_string().contains("unknown endpoint `missing`"));
}

#[test]
fn docker_capability_kind_parses_for_slots_and_provides() {
    let m: Manifest = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            network: { endpoints: [ { name: "endpoint", port: 80 } ] }
          },
          slots: {
            worker: { kind: "docker" }
          },
          provides: {
            api: { kind: "docker", endpoint: "endpoint" }
          },
          exports: { api: "api" },
        }
        "#
    .parse()
    .unwrap();

    let worker = m.slots.get("worker").expect("worker slot");
    assert_eq!(worker.decl.kind, CapabilityKind::Docker);

    let api = m.provides.get("api").expect("api provide");
    assert_eq!(api.decl.kind, CapabilityKind::Docker);
    assert_eq!(api.endpoint.as_deref(), Some("endpoint"));
}
