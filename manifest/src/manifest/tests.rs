use super::*;
use crate::{CapabilityKind, Endpoint, NetworkProtocol};

#[test]
fn create_empty_manifest() {
    let manifest = Manifest::empty();
    assert_eq!(manifest.manifest_version, Version::new(0, 1, 0));
    assert!(manifest.program.is_none());
    assert!(manifest.components.is_empty());
    assert!(manifest.environments.is_empty());
    assert!(manifest.config_schema.is_none());
    assert!(manifest.slots.is_empty());
    assert!(manifest.provides.is_empty());
    assert!(manifest.bindings.is_empty());
    assert!(manifest.exports.is_empty());
}

#[test]
fn component_config_null_normalizes_to_none() {
    let manifest: Manifest = r#"
        {
          manifest_version: "0.1.0",
          components: {
            child: { manifest: "file:///child.json5", config: null },
          },
        }
        "#
    .parse()
    .unwrap();

    let child = manifest
        .components()
        .get("child")
        .expect("child component should exist");
    let ComponentDecl::Object(obj) = child else {
        panic!("expected child component to be an object decl");
    };
    assert!(obj.config.is_none());
}

#[test]
fn manifest_version_requirement_is_enforced() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.2.0",
        }
        "#,
    );
    let err = raw.validate().unwrap_err();

    match err {
        Error::UnsupportedManifestVersion {
            version,
            supported_req,
        } => {
            assert_eq!(version, Version::new(0, 2, 0));
            assert_eq!(supported_req, "^0.1.0");
        }
        other => panic!("expected UnsupportedManifestVersion error, got: {other}"),
    }
}

#[test]
fn program_args_string_sugar_splits() {
    let m: Manifest = r#"
        {
          manifest_version: "0.1.0",
          program: { image: "x", args: "--foo ${config.bar} --baz" }
        }
        "#
    .parse()
    .unwrap();

    let args = &m.program.as_ref().unwrap().args.0;
    assert_eq!(args.len(), 3);
    assert_eq!(args[0].to_string(), "--foo");
    assert_eq!(args[1].to_string(), "${config.bar}");
    assert_eq!(args[2].to_string(), "--baz");
}

#[test]
fn binding_sugar_forms_parse() {
    let m: Manifest = r##"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
          components: {
            a: "https://example.com/a",
            b: "https://example.com/b",
          },
          provides: {
            d: { kind: "http", endpoint: "endpoint" },
          },
          bindings: [
            { to: "#a", slot: "s", from: "#b", capability: "c" },
            { to: "#a.s", from: "#b.c" },
            { to: "#a", slot: "t", from: "self", capability: "d" },
            { to: "#a.t", from: "self.d" },
          ],
        }
        "##
    .parse()
    .unwrap();

    let expected = BTreeMap::from([
        (
            BindingTarget::ChildSlot {
                child: ChildName::try_from("a").unwrap(),
                slot: SlotName::try_from("s").unwrap(),
            },
            Binding {
                name: None,
                from: BindingSource::ChildExport {
                    child: ChildName::try_from("b").unwrap(),
                    export: ExportName::try_from("c").unwrap(),
                },
                weak: false,
            },
        ),
        (
            BindingTarget::ChildSlot {
                child: ChildName::try_from("a").unwrap(),
                slot: SlotName::try_from("t").unwrap(),
            },
            Binding {
                name: None,
                from: BindingSource::SelfProvide(ProvideName::try_from("d").unwrap()),
                weak: false,
            },
        ),
    ]);

    assert_eq!(m.bindings, expected);
}

#[test]
fn binding_name_is_parsed() {
    let m: Manifest = r##"
        {
          manifest_version: "0.1.0",
          components: {
            a: "https://example.com/a",
            b: "https://example.com/b",
          },
          bindings: [
            { name: "link", to: "#a.s", from: "#b.c" },
          ],
        }
        "##
    .parse()
    .unwrap();

    let target = BindingTarget::ChildSlot {
        child: ChildName::try_from("a").unwrap(),
        slot: SlotName::try_from("s").unwrap(),
    };
    let binding = m.bindings.get(&target).expect("binding");
    assert_eq!(
        binding.name.as_ref().map(|name| name.as_str()),
        Some("link")
    );
}

#[test]
fn binding_component_refs_require_hash_for_children() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          bindings: [
            { to: "a.s", from: "self.c" },
          ],
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    assert!(err.to_string().contains("expected `self` or `#<child>`"));
}

#[test]
fn binding_target_framework_is_rejected() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          bindings: [
            { to: "framework", slot: "control", from: "self", capability: "api" },
          ],
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    assert!(
        err.to_string()
            .contains("framework cannot be a binding target")
    );
}

#[test]
fn export_target_framework_is_rejected() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          exports: {
            api: "framework.log",
          }
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    assert!(
        err.to_string()
            .contains("framework is only valid as a binding source")
    );
}

#[test]
fn binding_missing_capability_errors() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          bindings: [
            { to: "a", slot: "s", from: "b" }
          ],
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    assert!(err.to_string().contains("binding"));
}

#[test]
fn binding_dot_names_are_rejected_in_dot_form() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          bindings: [
            { to: "\#a.s", from: "self.c.d" },
          ],
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    assert!(err.to_string().contains("binding names cannot contain `.`"));
}

#[test]
fn binding_dot_names_are_rejected_in_explicit_form() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          bindings: [
            { to: "\#a", slot: "s.t", from: "self", capability: "c" },
          ],
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    assert!(err.to_string().contains("binding names cannot contain `.`"));
}

#[test]
fn binding_name_cannot_contain_dots() {
    let err = r##"
        {
          manifest_version: "0.1.0",
          components: {
            a: "https://example.com/a",
            b: "https://example.com/b",
          },
          bindings: [
            { name: "bad.name", to: "#a.s", from: "#b.c" },
          ],
        }
        "##
    .parse::<Manifest>()
    .unwrap_err();

    match err {
        Error::InvalidName { kind, name } => {
            assert_eq!(kind, "binding");
            assert_eq!(name, "bad.name");
        }
        other => panic!("expected InvalidName error, got: {other}"),
    }
}

#[test]
fn binding_mixed_form_is_rejected() {
    let err = r##"
        {
          manifest_version: "0.1.0",
          bindings: [
            { to: "#a.b", slot: "s", from: "self", capability: "c" },
          ],
        }
        "##
    .parse::<Manifest>()
    .unwrap_err();

    match err {
        Error::MixedBindingForm { to, from } => {
            assert_eq!(to, "#a.b");
            assert_eq!(from, "self");
        }
        other => panic!("expected MixedBindingForm error, got: {other}"),
    }
}

#[test]
fn binding_round_trip_through_canonical_json_parses() {
    let m: Manifest = r##"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
          components: {
            a: "https://example.com/a",
          },
          provides: {
            c: { kind: "http", endpoint: "endpoint" },
          },
          bindings: [
            { name: "link", to: "#a.s", from: "self.c" },
          ],
        }
        "##
    .parse()
    .unwrap();

    let json = serde_json::to_string_pretty(&m).unwrap();
    let round_tripped: Manifest = json.parse().unwrap();
    assert_eq!(round_tripped, m);
}

#[test]
fn binding_to_self_is_disallowed() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          components: {
            child: "https://example.com/child",
          },
          bindings: [
            { to: "self.needs", from: "\#child.api" },
          ],
        }
        "#,
    );
    let err = raw.validate().unwrap_err();

    match err {
        Error::BindingTargetSelfSlot { slot } => assert_eq!(slot, "needs"),
        other => panic!("expected BindingTargetSelfSlot error, got: {other}"),
    }
}

#[test]
fn binding_from_self_requires_slot_or_provide() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          components: {
            child: "https://example.com/child",
          },
          bindings: [
            { to: "\#child.needs", from: "self.api" },
          ],
        }
        "#,
    );
    let err = raw.validate().unwrap_err();

    match err {
        Error::UnknownBindingSource { capability } => assert_eq!(capability, "api"),
        other => panic!("expected UnknownBindingSource error, got: {other}"),
    }
}

#[test]
fn binding_from_self_slot_is_allowed() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          slots: {
            api: { kind: "http" },
          },
          components: {
            child: "https://example.com/child",
          },
          bindings: [
            { to: "\#child.api", from: "self.api" },
          ],
        }
        "#,
    );

    let manifest = raw.validate().unwrap();
    let target = BindingTarget::ChildSlot {
        child: ChildName::try_from("child").unwrap(),
        slot: SlotName::try_from("api").unwrap(),
    };
    let binding = manifest.bindings().get(&target).expect("binding");
    assert!(matches!(binding.from, BindingSource::SelfSlot(_)));
}

#[test]
fn binding_from_framework_requires_known_capability_explicit_form() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          components: {
            child: "https://example.com/child",
          },
          bindings: [
            { to: "\#child", slot: "control", from: "framework", capability: "dynamic_children" },
          ],
        }
        "#,
    );
    let err = raw.validate().unwrap_err();

    match err {
        Error::UnknownFrameworkCapability { capability, help } => {
            assert_eq!(capability, "dynamic_children");
            assert!(help.contains("framework exposes no capabilities yet"));
        }
        other => panic!("expected UnknownFrameworkCapability error, got: {other}"),
    }
}

#[test]
fn binding_from_framework_requires_known_capability_dot_form() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          components: {
            child: "https://example.com/child",
          },
          bindings: [
            { to: "\#child.control", from: "framework.dynamic_children" },
          ],
        }
        "#,
    );
    let err = raw.validate().unwrap_err();

    match err {
        Error::UnknownFrameworkCapability { capability, help } => {
            assert_eq!(capability, "dynamic_children");
            assert!(help.contains("framework exposes no capabilities yet"));
        }
        other => panic!("expected UnknownFrameworkCapability error, got: {other}"),
    }
}

#[test]
fn binding_child_ref_requires_component() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          components: {
            other: "https://example.com/other",
          },
          bindings: [
            { to: "\#missing.needs", from: "\#other.api" },
          ],
        }
        "#,
    );
    let err = raw.validate().unwrap_err();

    match err {
        Error::UnknownBindingChild { child } => assert_eq!(child, "missing"),
        other => panic!("expected UnknownBindingChild error, got: {other}"),
    }
}

#[test]
fn manifest_deserialize_error_includes_path() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            network: { endpoints: [ { name: "endpoint", port: "80" } ] }
          }
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    match err {
        Error::Json5Path(err) => {
            assert_eq!(err.path(), Some("program.network.endpoints[0].port"));
        }
        other => panic!("expected Json5Path error, got: {other}"),
    }
}

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
    assert_eq!(program.image, "x");

    let network = program.network.as_ref().expect("network");
    assert_eq!(network.endpoints.len(), 1);
    assert!(network.endpoints.contains(&Endpoint {
        name: "endpoint".to_string(),
        port: 80,
        protocol: NetworkProtocol::Http,
    }));

    let api = m.provides.get("api").expect("api provide");
    assert_eq!(api.decl.kind, CapabilityKind::Http);
    assert_eq!(api.endpoint.as_deref(), Some("endpoint"));
    assert!(m.exports.contains_key("api"));
}

#[test]
fn duplicate_keys_in_components_map_errors() {
    let res: Result<Manifest, _> = r##"
        {
          manifest_version: "0.1.0",
          components: {
            a: "https://example.com/amber/pkg/v1",
            a: "https://example.com/amber/other/v2",
          }
        }
        "##
    .parse();

    assert!(res.is_err());
}

#[test]
fn duplicate_keys_in_program_env_errors() {
    let res: Result<Manifest, _> = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            env: { FOO: "a", FOO: "b" }
          }
        }
        "#
    .parse();

    assert!(res.is_err());
}

#[test]
fn child_names_cannot_contain_dots() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          components: {
            "a.b": "https://example.com/amber/pkg/v1",
          },
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    assert!(err.to_string().contains("invalid child name `a.b`"));
}

#[test]
fn slot_names_cannot_contain_dots() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          slots: {
            "llm.v1": { kind: "llm" },
          },
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    assert!(err.to_string().contains("invalid slot name `llm.v1`"));
}

#[test]
fn provide_names_cannot_contain_dots() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          provides: {
            "api.v1": { kind: "http", endpoint: "endpoint" },
          },
          program: {
            image: "x",
            entrypoint: ["x"],
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    assert!(err.to_string().contains("invalid provide name `api.v1`"));
}

#[test]
fn export_names_cannot_contain_dots() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          exports: { "api.v1": "api" },
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    assert!(err.to_string().contains("invalid export name `api.v1`"));
}

#[test]
fn export_target_names_cannot_contain_dots() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          exports: { api: "self.api.v1" },
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    assert!(
        err.to_string()
            .contains("invalid export target name `api.v1`")
    );
}

#[test]
fn export_target_unknown_capability_errors() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          exports: { api: "missing" },
        }
        "#,
    );
    let err = raw.validate().unwrap_err();

    match err {
        Error::UnknownExportTarget { export, target } => {
            assert_eq!(export, "api");
            assert_eq!(target, "missing");
        }
        other => panic!("expected UnknownExportTarget error, got: {other}"),
    }
}

#[test]
fn export_target_slot_is_allowed() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          slots: { llm: { kind: "llm" } },
          exports: { llm: "llm" },
        }
        "#,
    );
    let manifest = raw.validate().unwrap();
    let export_name = ExportName::try_from("llm").unwrap();
    let target = manifest.exports().get(&export_name).expect("export target");
    assert!(matches!(target, ExportTarget::SelfSlot(_)));
}

#[test]
fn export_target_unknown_child_errors() {
    let raw = parse_raw(
        r##"
        {
          manifest_version: "0.1.0",
          exports: { api: "#missing.api" },
        }
        "##,
    );
    let err = raw.validate().unwrap_err();

    match err {
        Error::UnknownExportChild { export, child } => {
            assert_eq!(export, "api");
            assert_eq!(child, "missing");
        }
        other => panic!("expected UnknownExportChild error, got: {other}"),
    }
}

#[test]
fn export_targets_serialize_with_self_prefix() {
    let manifest: Manifest = r#"
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
    .parse()
    .unwrap();

    let value = serde_json::to_value(&manifest).unwrap();
    let export = value
        .get("exports")
        .and_then(|exports| exports.get("api"))
        .and_then(|export| export.as_str());

    assert_eq!(export, Some("self.api"));
}

#[test]
fn slots_and_provides_cannot_share_names() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
          slots: { api: { kind: "http" } },
          provides: { api: { kind: "http", endpoint: "endpoint" } },
          exports: { api: "api" },
        }
        "#,
    );
    let err = raw.validate().unwrap_err();

    match err {
        Error::AmbiguousCapabilityName { name } => assert_eq!(name, "api"),
        other => panic!("expected AmbiguousCapabilityName error, got: {other}"),
    }
}

#[test]
fn binding_target_cannot_be_multiplexed() {
    let raw = parse_raw(
        r##"
        {
          manifest_version: "0.1.0",
          components: {
            a: "https://example.com/a",
            b: "https://example.com/b",
            c: "https://example.com/c",
          },
          bindings: [
            { to: "#a.s", from: "#b.c" },
            { to: "#a.s", from: "#c.d" },
          ],
        }
        "##,
    );
    let err = raw.validate().unwrap_err();

    match err {
        Error::DuplicateBindingTarget { to, slot } => {
            assert_eq!(to, "#a");
            assert_eq!(slot, "s");
        }
        other => panic!("expected DuplicateBindingTarget error, got: {other}"),
    }
}

#[test]
fn binding_name_must_be_unique() {
    let raw = parse_raw(
        r##"
        {
          manifest_version: "0.1.0",
          components: {
            a: "https://example.com/a",
            b: "https://example.com/b",
          },
          bindings: [
            { name: "dup", to: "#a.s", from: "#b.c" },
            { name: "dup", to: "#a.t", from: "#b.d" },
          ],
        }
        "##,
    );
    let err = raw.validate().unwrap_err();

    match err {
        Error::DuplicateBindingName { name } => assert_eq!(name, "dup"),
        other => panic!("expected DuplicateBindingName error, got: {other}"),
    }
}

#[test]
fn binding_source_can_be_multiplexed() {
    let raw = parse_raw(
        r##"
        {
          manifest_version: "0.1.0",
          components: {
            a: "https://example.com/a",
            b: "https://example.com/b",
          },
          bindings: [
            { to: "#a.s1", from: "#b.c" },
            { to: "#a.s2", from: "#b.c" },
          ],
        }
        "##,
    );

    let m = raw.validate().unwrap();

    let expected = BTreeMap::from([
        (
            BindingTarget::ChildSlot {
                child: ChildName::try_from("a").unwrap(),
                slot: SlotName::try_from("s1").unwrap(),
            },
            Binding {
                name: None,
                from: BindingSource::ChildExport {
                    child: ChildName::try_from("b").unwrap(),
                    export: ExportName::try_from("c").unwrap(),
                },
                weak: false,
            },
        ),
        (
            BindingTarget::ChildSlot {
                child: ChildName::try_from("a").unwrap(),
                slot: SlotName::try_from("s2").unwrap(),
            },
            Binding {
                name: None,
                from: BindingSource::ChildExport {
                    child: ChildName::try_from("b").unwrap(),
                    export: ExportName::try_from("c").unwrap(),
                },
                weak: false,
            },
        ),
    ]);

    assert_eq!(m.bindings, expected);
}

fn parse_raw(input: &str) -> RawManifest {
    amber_json5::parse(input).unwrap()
}
