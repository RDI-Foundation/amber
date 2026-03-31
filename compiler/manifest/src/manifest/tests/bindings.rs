use super::*;

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
    assert!(json.contains("\"from\": \"provides\""), "{json}");
    assert!(json.contains("\"capability\": \"c\""), "{json}");
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
        Error::UnknownBindingSource {
            reference,
            expected,
        } => {
            assert_eq!(reference, "self.api");
            assert_eq!(expected, "slot or provide");
        }
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
fn binding_from_explicit_slot_ref_is_allowed() {
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
            { to: "\#child.api", from: "slots.api" },
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
fn binding_from_explicit_provide_ref_is_allowed() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
          provides: {
            api: { kind: "http", endpoint: "endpoint" },
          },
          components: {
            child: "https://example.com/child",
          },
          bindings: [
            { to: "\#child.api", from: "provides.api" },
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
    assert!(matches!(binding.from, BindingSource::SelfProvide(_)));
}

#[test]
fn binding_from_slots_ref_requires_declared_slot() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          components: {
            child: "https://example.com/child",
          },
          bindings: [
            { to: "\#child.needs", from: "slots.api" },
          ],
        }
        "#,
    );
    let err = raw.validate().unwrap_err();

    match err {
        Error::UnknownBindingSource {
            reference,
            expected,
        } => {
            assert_eq!(reference, "slots.api");
            assert_eq!(expected, "slot");
        }
        other => panic!("expected UnknownBindingSource error, got: {other}"),
    }
}

#[test]
fn binding_from_provides_ref_requires_declared_provide() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          components: {
            child: "https://example.com/child",
          },
          bindings: [
            { to: "\#child.needs", from: "provides.api" },
          ],
        }
        "#,
    );
    let err = raw.validate().unwrap_err();

    match err {
        Error::UnknownBindingSource {
            reference,
            expected,
        } => {
            assert_eq!(reference, "provides.api");
            assert_eq!(expected, "provide");
        }
        other => panic!("expected UnknownBindingSource error, got: {other}"),
    }
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
