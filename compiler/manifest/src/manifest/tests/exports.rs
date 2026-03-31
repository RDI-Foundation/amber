use super::*;

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
        Error::UnknownExportTarget {
            export,
            target,
            expected,
        } => {
            assert_eq!(export, "api");
            assert_eq!(target, "missing");
            assert_eq!(expected, "capability");
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
fn export_target_explicit_slot_is_allowed() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          slots: { llm: { kind: "llm" } },
          exports: { llm: "slots.llm" },
        }
        "#,
    );

    let manifest = raw.validate().unwrap();
    let target = manifest.exports().get("llm").unwrap();
    assert!(matches!(target, ExportTarget::SelfSlot(_)));
}

#[test]
fn export_target_explicit_provide_is_allowed() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
          provides: { llm: { kind: "http", endpoint: "endpoint" } },
          exports: { llm: "provides.llm" },
        }
        "#,
    );

    let manifest = raw.validate().unwrap();
    let target = manifest.exports().get("llm").unwrap();
    assert!(matches!(target, ExportTarget::SelfProvide(_)));
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
fn export_targets_serialize_with_explicit_local_prefixes() {
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

    assert_eq!(export, Some("provides.api"));
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
