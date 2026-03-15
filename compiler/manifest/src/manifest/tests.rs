use super::*;
use crate::{CapabilityKind, NetworkProtocol};

#[test]
fn create_empty_manifest() {
    let manifest = Manifest::empty();
    assert_eq!(manifest.manifest_version, Version::new(0, 2, 0));
    assert!(manifest.experimental_features.is_empty());
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
fn experimental_features_parse() {
    let manifest: Manifest = r#"
        {
          manifest_version: "0.1.0",
          experimental_features: ["docker"],
        }
        "#
    .parse()
    .unwrap();

    assert!(
        manifest
            .experimental_features()
            .contains(&ExperimentalFeature::Docker)
    );
}

#[test]
fn unknown_experimental_feature_is_rejected() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          experimental_features: ["not_a_real_feature"],
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    let message = err.to_string();
    assert!(
        message.contains("unknown variant `not_a_real_feature`"),
        "unexpected error message: {message}"
    );
}

#[test]
fn duplicate_experimental_features_are_deduplicated() {
    let manifest: Manifest = r#"
        {
          manifest_version: "0.1.0",
          experimental_features: ["docker", "docker"],
        }
        "#
    .parse()
    .unwrap();

    assert_eq!(manifest.experimental_features().len(), 1);
    assert!(
        manifest
            .experimental_features()
            .contains(&ExperimentalFeature::Docker)
    );
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
          manifest_version: "1.0.0",
        }
        "#,
    );
    let err = raw.validate().unwrap_err();

    match err {
        Error::UnsupportedManifestVersion {
            version,
            supported_req,
        } => {
            assert_eq!(version, Version::new(1, 0, 0));
            assert_eq!(supported_req, ">=0.1.0, <1.0.0");
        }
        other => panic!("expected UnsupportedManifestVersion error, got: {other}"),
    }
}

#[test]
fn legacy_manifest_version_is_accepted() {
    let manifest: Manifest = r#"
        {
          manifest_version: "0.1.0",
        }
    "#
    .parse()
    .unwrap();

    assert_eq!(manifest.manifest_version(), &Version::new(0, 1, 0));
}

#[test]
fn conditional_program_args_require_manifest_version_0_2_0() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            path: "/bin/echo",
            args: [
              {
                when: "config.profile",
                argv: ["--profile", "${config.profile}"],
              },
            ],
          },
        }
        "#,
    );
    let err = raw.validate().unwrap_err();

    match err {
        Error::UnsupportedProgramSyntaxForManifestVersion {
            manifest_version,
            required_version,
            feature,
            pointer,
        } => {
            assert_eq!(*manifest_version, Version::new(0, 1, 0));
            assert_eq!(required_version, "0.2.0");
            assert_eq!(feature, "conditional argument items");
            assert_eq!(pointer, "/program/args/0");
        }
        other => panic!("expected UnsupportedProgramSyntaxForManifestVersion error, got: {other}"),
    }
}

#[test]
fn when_is_accepted_in_manifest_version_0_2_0() {
    let manifest: Manifest = r#"
        {
          manifest_version: "0.2.0",
          program: {
            path: "/bin/echo",
            args: [
              {
                when: "config.profile",
                argv: ["--profile", "${config.profile}"],
              },
            ],
          },
        }
    "#
    .parse()
    .unwrap();

    let Program::Path(program) = manifest.program().expect("program should exist") else {
        panic!("expected native path program");
    };
    assert_eq!(
        program
            .args
            .0
            .iter()
            .filter(|item| item.when().is_some())
            .count(),
        1
    );
}

#[test]
fn conditional_program_env_requires_manifest_version_0_2_0() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "busybox:1.36",
            env: {
              PROFILE: {
                when: "config.profile",
                value: "${config.profile}",
              },
            },
          },
        }
        "#,
    );
    let err = raw.validate().unwrap_err();

    match err {
        Error::UnsupportedProgramSyntaxForManifestVersion {
            manifest_version,
            required_version,
            feature,
            pointer,
        } => {
            assert_eq!(*manifest_version, Version::new(0, 1, 0));
            assert_eq!(required_version, "0.2.0");
            assert_eq!(feature, "conditional environment values");
            assert_eq!(pointer, "/program/env/PROFILE");
        }
        other => panic!("expected UnsupportedProgramSyntaxForManifestVersion error, got: {other}"),
    }
}

#[test]
fn conditional_program_env_is_accepted_in_manifest_version_0_2_0() {
    let manifest: Manifest = r#"
        {
          manifest_version: "0.2.0",
          program: {
            image: "busybox:1.36",
            entrypoint: ["env"],
            env: {
              PROFILE: {
                when: "config.profile",
                value: "${config.profile}",
              },
            },
          },
        }
    "#
    .parse()
    .unwrap();

    let Program::Image(program) = manifest.program().expect("program should exist") else {
        panic!("expected image program");
    };
    assert!(
        program
            .common
            .env
            .get("PROFILE")
            .is_some_and(|value| value.when().is_some())
    );
}

#[test]
fn conditional_vm_mounts_require_manifest_version_0_2_0() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          config_schema: {
            type: "object",
            properties: {
              enabled: { type: "boolean" },
              value: { type: "string" },
            },
          },
          program: {
            vm: {
              image: "debian-13",
              cpus: 1,
              memory_mib: 512,
              mounts: [
                {
                  when: "config.enabled",
                  path: "/run/app.txt",
                  from: "config.value",
                },
              ],
            },
          },
        }
        "#,
    );
    let err = raw.validate().unwrap_err();

    match err {
        Error::UnsupportedProgramSyntaxForManifestVersion {
            manifest_version,
            required_version,
            feature,
            pointer,
        } => {
            assert_eq!(*manifest_version, Version::new(0, 1, 0));
            assert_eq!(required_version, "0.2.0");
            assert_eq!(feature, "conditional mounts");
            assert_eq!(pointer, "/program/vm/mounts/0");
        }
        other => panic!("expected UnsupportedProgramSyntaxForManifestVersion error, got: {other}"),
    }
}

#[test]
fn variadic_vm_endpoints_require_manifest_version_0_3_0() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.2.0",
          config_schema: {
            type: "object",
            properties: {
              listeners: {
                type: "array",
                items: { type: "string" },
              },
            },
          },
          program: {
            vm: {
              image: "debian-13",
              cpus: 1,
              memory_mib: 512,
              network: {
                endpoints: [
                  {
                    each: "config.listeners",
                    name: "${item}",
                    port: 8080,
                    protocol: "http",
                  },
                ],
              },
            },
          },
        }
        "#,
    );
    let err = raw.validate().unwrap_err();

    match err {
        Error::UnsupportedProgramSyntaxForManifestVersion {
            manifest_version,
            required_version,
            feature,
            pointer,
        } => {
            assert_eq!(*manifest_version, Version::new(0, 2, 0));
            assert_eq!(required_version, "0.3.0");
            assert_eq!(feature, "variadic endpoints");
            assert_eq!(pointer, "/program/vm/network/endpoints/0");
        }
        other => panic!("expected UnsupportedProgramSyntaxForManifestVersion error, got: {other}"),
    }
}

#[test]
fn program_entrypoint_string_sugar_splits() {
    let m: Manifest = r#"
        {
          manifest_version: "0.1.0",
          program: { image: "x", entrypoint: "--foo ${config.bar} --baz" }
        }
        "#
    .parse()
    .unwrap();

    let Program::Image(program) = m.program.as_ref().unwrap() else {
        panic!("expected image program");
    };
    let entrypoint = &program.entrypoint.0;
    assert_eq!(entrypoint.len(), 3);
    assert_eq!(entrypoint[0].arg().unwrap().to_string(), "--foo");
    assert_eq!(entrypoint[1].arg().unwrap().to_string(), "${config.bar}");
    assert_eq!(entrypoint[2].arg().unwrap().to_string(), "--baz");
}

#[test]
fn program_image_supports_interpolation_syntax() {
    let m: Manifest = r#"
        {
          manifest_version: "0.1.0",
          config_schema: {
            type: "object",
            properties: { image: { type: "string" } },
          },
          program: {
            image: "${config.image}",
            entrypoint: ["x"],
          }
        }
        "#
    .parse()
    .unwrap();

    let program = m.program.as_ref().expect("program should exist");
    assert_eq!(program.image_ref(), Some("${config.image}"));
}

#[test]
fn invalid_program_image_interpolation_syntax_errors() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "${config.image",
            entrypoint: ["x"],
          }
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("invalid interpolation"), "{msg}");
}

#[test]
fn program_path_args_string_sugar_splits() {
    let manifest: Manifest = r#"
        {
          manifest_version: "0.1.0",
          program: {
            path: "/usr/bin/env",
            args: "python3 -m http.server 8080",
          }
        }
        "#
    .parse()
    .unwrap();

    let Program::Path(program) = manifest.program.as_ref().expect("program should exist") else {
        panic!("expected native path program");
    };
    assert_eq!(program.args.0.len(), 4);
    assert_eq!(program.args.0[0].arg().unwrap().to_string(), "python3");
    assert_eq!(program.args.0[1].arg().unwrap().to_string(), "-m");
    assert_eq!(program.args.0[2].arg().unwrap().to_string(), "http.server");
    assert_eq!(program.args.0[3].arg().unwrap().to_string(), "8080");
}

#[test]
fn program_requires_exactly_one_source_field() {
    let both = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            path: "/bin/true",
            entrypoint: ["x"],
          }
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();
    assert!(
        both.to_string()
            .contains("exactly one of `image`, `path`, or `vm`")
    );

    let neither = r#"
        {
          manifest_version: "0.1.0",
          program: {
            env: { X: "1" },
          }
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();
    assert!(
        neither
            .to_string()
            .contains("either `image`, `path`, or `vm`")
    );
}

#[test]
fn program_path_rejects_entrypoint_field() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          program: {
            path: "/bin/true",
            entrypoint: ["run"],
          }
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("program.entrypoint is only supported with program.image")
    );
}

#[test]
fn program_path_rejects_empty_entrypoint_field() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          program: {
            path: "/bin/true",
            entrypoint: [],
          }
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("program.entrypoint is only supported with program.image")
    );
}

#[test]
fn program_path_rejects_null_entrypoint_field() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          program: {
            path: "/bin/true",
            entrypoint: null,
          }
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("program.entrypoint is only supported with program.image")
    );
}

#[test]
fn program_image_rejects_empty_args_field() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "example:latest",
            entrypoint: ["/bin/true"],
            args: [],
          }
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("program.args is only supported with program.path")
    );
}

#[test]
fn program_image_rejects_null_args_field() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "example:latest",
            entrypoint: ["/bin/true"],
            args: null,
          }
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("program.args is only supported with program.path")
    );
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

    let expected = vec![
        ManifestBinding {
            target: BindingTarget::ChildSlot {
                child: ChildName::try_from("a").unwrap(),
                slot: SlotName::try_from("s").unwrap(),
            },
            binding: Binding {
                from: BindingSource::ChildExport {
                    child: ChildName::try_from("b").unwrap(),
                    export: ExportName::try_from("c").unwrap(),
                },
                weak: false,
            },
        },
        ManifestBinding {
            target: BindingTarget::ChildSlot {
                child: ChildName::try_from("a").unwrap(),
                slot: SlotName::try_from("s").unwrap(),
            },
            binding: Binding {
                from: BindingSource::ChildExport {
                    child: ChildName::try_from("b").unwrap(),
                    export: ExportName::try_from("c").unwrap(),
                },
                weak: false,
            },
        },
        ManifestBinding {
            target: BindingTarget::ChildSlot {
                child: ChildName::try_from("a").unwrap(),
                slot: SlotName::try_from("t").unwrap(),
            },
            binding: Binding {
                from: BindingSource::SelfProvide(ProvideName::try_from("d").unwrap()),
                weak: false,
            },
        },
        ManifestBinding {
            target: BindingTarget::ChildSlot {
                child: ChildName::try_from("a").unwrap(),
                slot: SlotName::try_from("t").unwrap(),
            },
            binding: Binding {
                from: BindingSource::SelfProvide(ProvideName::try_from("d").unwrap()),
                weak: false,
            },
        },
    ];

    assert_eq!(m.bindings, expected);
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
            { to: "#a.s", from: "self.c" },
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
fn binding_to_self_is_disallowed_because_slots_are_parent_inputs() {
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
    let binding = find_binding(&manifest, &target);
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
            assert!(help.contains("Known framework capabilities: docker"));
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
            assert!(help.contains("Known framework capabilities: docker"));
        }
        other => panic!("expected UnknownFrameworkCapability error, got: {other}"),
    }
}

#[test]
fn binding_from_framework_docker_requires_experimental_feature() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          components: {
            child: "https://example.com/child",
          },
          bindings: [
            { to: "\#child.worker", from: "framework.docker" },
          ],
        }
        "#,
    );
    let err = raw.validate().unwrap_err();

    match err {
        Error::FrameworkCapabilityRequiresFeature {
            capability,
            feature,
        } => {
            assert_eq!(capability, "docker");
            assert_eq!(feature, "docker");
        }
        other => panic!("expected FrameworkCapabilityRequiresFeature error, got: {other}"),
    }
}

#[test]
fn binding_from_framework_docker_is_allowed_with_experimental_feature() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          experimental_features: ["docker"],
          components: {
            child: "https://example.com/child",
          },
          bindings: [
            { to: "\#child.worker", from: "framework.docker" },
          ],
        }
        "#,
    );
    let manifest = raw.validate().expect("manifest should validate");
    let target = BindingTarget::ChildSlot {
        child: ChildName::try_from("child").unwrap(),
        slot: SlotName::try_from("worker").unwrap(),
    };
    let binding = find_binding(&manifest, &target);
    let BindingSource::Framework(name) = &binding.from else {
        panic!("expected framework binding source");
    };
    assert_eq!(name.as_str(), "docker");
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
            network: { endpoints: [ { name: "endpoint", port: { value: 80 } } ] }
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

#[test]
fn mounts_parse_config_sources_for_plain_and_secret_paths() {
    let m: Manifest = r#"
        {
          manifest_version: "0.1.0",
          config_schema: {
            type: "object",
            properties: {
              app: { type: "string" },
              token: { type: "string", secret: true },
            },
            required: ["app", "token"],
          },
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/run/app.txt", from: "config.app" },
              { path: "/run/token.txt", from: "config.token" },
            ]
          }
        }
        "#
    .parse()
    .unwrap();

    let program = m.program.as_ref().expect("program");
    assert_eq!(program.mounts().len(), 2);
}

#[test]
fn storage_mount_source_parses_for_storage_slots() {
    let manifest: Manifest = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/var/lib/app", from: "slots.state" },
            ]
          },
          slots: {
            state: { kind: "storage" },
          },
        }
        "#
    .parse()
    .unwrap();

    let program = manifest.program.as_ref().expect("program");
    assert_eq!(program.mounts().len(), 1);
    assert_eq!(program.mounts()[0].source.to_string(), "slots.state");
}

#[test]
fn storage_mount_source_parses_for_local_resources() {
    let manifest: Manifest = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/var/lib/app", from: "resources.state" },
            ]
          },
          resources: {
            state: { kind: "storage" },
          },
        }
        "#
    .parse()
    .unwrap();

    let program = manifest.program.as_ref().expect("program");
    assert_eq!(program.mounts().len(), 1);
    assert_eq!(program.mounts()[0].source.to_string(), "resources.state");
}

#[test]
fn storage_resource_parses_without_source() {
    let manifest: Manifest = r#"
        {
          manifest_version: "0.1.0",
          resources: {
            state: { kind: "storage" },
          },
        }
        "#
    .parse()
    .unwrap();

    let resource = manifest.resources().get("state").expect("resource");
    assert_eq!(resource.kind, CapabilityKind::Storage);
}

#[test]
fn storage_resource_param_parses_interpolation() {
    let manifest: Manifest = r#"
        {
          manifest_version: "0.1.0",
          resources: {
            state: {
              kind: "storage",
              params: { size: "${config.storage_size}" },
            },
          },
        }
        "#
    .parse()
    .unwrap();

    let resource = manifest.resources().get("state").expect("resource");
    assert_eq!(
        resource
            .params
            .size
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        Some("${config.storage_size}")
    );
}

#[test]
fn storage_mount_rejects_unknown_slot() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/var/lib/app", from: "slots.state" },
            ]
          }
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    match err {
        Error::UnknownMountSlot { slot } => assert_eq!(slot, "state"),
        other => panic!("expected UnknownMountSlot error, got: {other}"),
    }
}

#[test]
fn storage_mount_rejects_unknown_resource() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/var/lib/app", from: "resources.state" },
            ]
          }
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    match err {
        Error::UnknownMountResource { resource } => assert_eq!(resource, "state"),
        other => panic!("expected UnknownMountResource error, got: {other}"),
    }
}

#[test]
fn storage_mount_rejects_non_storage_slot() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/var/lib/app", from: "slots.api" },
            ]
          },
          slots: {
            api: { kind: "http" },
          },
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    match err {
        Error::MountSlotRequiresStorage { slot, kind } => {
            assert_eq!(slot, "api");
            assert_eq!(kind, CapabilityKind::Http);
        }
        other => panic!("expected MountSlotRequiresStorage error, got: {other}"),
    }
}

#[test]
fn storage_provide_is_rejected() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
          },
          provides: {
            state: { kind: "storage", endpoint: "ignored" },
          },
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    match err {
        Error::UnsupportedProvideKind { name, kind } => {
            assert_eq!(name, "state");
            assert_eq!(kind, CapabilityKind::Storage);
        }
        other => panic!("expected UnsupportedProvideKind error, got: {other}"),
    }
}

#[test]
fn framework_docker_mount_requires_experimental_feature() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/var/run/docker.sock", from: "framework.docker" },
            ]
          }
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    match err {
        Error::FrameworkCapabilityRequiresFeature {
            capability,
            feature,
        } => {
            assert_eq!(capability, "docker");
            assert_eq!(feature, "docker");
        }
        other => panic!("expected FrameworkCapabilityRequiresFeature error, got: {other}"),
    }
}

#[test]
fn framework_docker_mount_is_allowed_with_experimental_feature() {
    let m: Manifest = r#"
        {
          manifest_version: "0.1.0",
          experimental_features: ["docker"],
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/var/run/docker.sock", from: "framework.docker" },
            ]
          }
        }
        "#
    .parse()
    .unwrap();

    let program = m.program.as_ref().expect("program");
    assert_eq!(program.mounts().len(), 1);
    assert_eq!(program.mounts()[0].source.to_string(), "framework.docker");
}

#[test]
fn config_mount_accepts_secret_path() {
    let manifest: Manifest = r#"
        {
          manifest_version: "0.1.0",
          config_schema: {
            type: "object",
            properties: {
              token: { type: "string", secret: true },
            },
          },
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/run/token.txt", from: "config.token" },
            ]
          }
        }
        "#
    .parse()
    .unwrap();

    assert_eq!(
        manifest.program.as_ref().expect("program").mounts().len(),
        1
    );
}

#[test]
fn secret_mount_source_is_rejected() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          config_schema: {
            type: "object",
            properties: {
              token: { type: "string" },
            },
          },
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/run/token.txt", from: "secret.token" },
            ]
          }
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    assert!(err.to_string().contains("invalid mount source"));
    assert!(err.to_string().contains("unknown mount source"));
}

#[test]
fn duplicate_mount_paths_error() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          config_schema: {
            type: "object",
            properties: {
              app: { type: "string" },
            },
          },
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/run/app.txt", from: "config.app" },
              { path: "/run/app.txt", from: "config.app" },
            ]
          }
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    assert!(err.to_string().contains("duplicate mount path"));
}

#[test]
fn conditional_mounts_still_validate_storage_sources() {
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
            mounts: [
              { when: "config.enabled", path: "/var/lib/app", from: "slots.state" },
            ]
          }
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    match err {
        Error::UnknownMountSlot { slot } => assert_eq!(slot, "state"),
        other => panic!("expected UnknownMountSlot error, got: {other}"),
    }
}

#[test]
fn interpolated_mount_paths_still_validate_literal_storage_sources() {
    let err = r#"
        {
          manifest_version: "0.3.0",
          config_schema: {
            type: "object",
            properties: {
              filename: { type: "string" },
            },
          },
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/var/${config.filename}", from: "slots.state" },
            ]
          }
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    match err {
        Error::UnknownMountSlot { slot } => assert_eq!(slot, "state"),
        other => panic!("expected UnknownMountSlot error, got: {other}"),
    }
}

#[test]
fn interpolated_non_file_mount_sources_are_preserved_for_link_time_resolution() {
    let manifest = r#"
        {
          manifest_version: "0.3.0",
          config_schema: {
            type: "object",
            properties: {
              source_kind: { type: "string" },
            },
          },
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/var/lib/app", from: "resources.${config.source_kind}" },
            ]
          }
        }
        "#
    .parse::<Manifest>()
    .expect("manifest");

    assert_eq!(
        manifest.program().expect("program").mounts()[0]
            .source
            .to_string(),
        "resources.${config.source_kind}"
    );
}

#[test]
fn fully_dynamic_mount_sources_are_preserved_for_link_time_resolution() {
    let manifest = r#"
        {
          manifest_version: "0.3.0",
          config_schema: {
            type: "object",
            properties: {
              mount_source: { type: "string" },
            },
          },
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/var/lib/app", from: "${config.mount_source}" },
            ]
          }
        }
        "#
    .parse::<Manifest>()
    .expect("manifest");

    assert_eq!(
        manifest.program().expect("program").mounts()[0]
            .source
            .to_string(),
        "${config.mount_source}"
    );
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
    let manifest = raw
        .validate()
        .expect("manifest should preserve duplicate targets");
    assert_eq!(manifest.bindings().len(), 2);
    let target = BindingTarget::ChildSlot {
        child: ChildName::try_from("a").unwrap(),
        slot: SlotName::try_from("s").unwrap(),
    };
    assert!(
        manifest
            .bindings()
            .iter()
            .all(|binding| binding.target == target)
    );
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

    let expected = vec![
        ManifestBinding {
            target: BindingTarget::ChildSlot {
                child: ChildName::try_from("a").unwrap(),
                slot: SlotName::try_from("s1").unwrap(),
            },
            binding: Binding {
                from: BindingSource::ChildExport {
                    child: ChildName::try_from("b").unwrap(),
                    export: ExportName::try_from("c").unwrap(),
                },
                weak: false,
            },
        },
        ManifestBinding {
            target: BindingTarget::ChildSlot {
                child: ChildName::try_from("a").unwrap(),
                slot: SlotName::try_from("s2").unwrap(),
            },
            binding: Binding {
                from: BindingSource::ChildExport {
                    child: ChildName::try_from("b").unwrap(),
                    export: ExportName::try_from("c").unwrap(),
                },
                weak: false,
            },
        },
    ];

    assert_eq!(m.bindings, expected);
}

fn parse_raw(input: &str) -> RawManifest {
    amber_json5::parse(input).unwrap()
}

fn find_binding<'a>(manifest: &'a Manifest, target: &BindingTarget) -> &'a Binding {
    manifest
        .bindings()
        .iter()
        .find(|binding| &binding.target == target)
        .map(|binding| &binding.binding)
        .expect("binding")
}
