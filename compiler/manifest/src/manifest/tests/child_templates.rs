use super::*;

#[test]
fn child_templates_require_component_slot() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          child_templates: {
            worker: {
              manifest: "https://example.com/worker.json5",
            },
          },
        }
        "#,
    );
    let err = raw.validate().unwrap_err();

    assert!(matches!(err, Error::ChildTemplatesRequireComponentSlot));
}

#[test]
fn child_template_manifest_may_be_omitted() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          slots: {
            realm: { kind: "component" },
          },
          child_templates: {
            worker: {
              bindings: {
                realm: "slots.realm",
              },
            },
          },
        }
        "#,
    );
    raw.validate()
        .expect("omitted child-template manifest should remain valid");
}

#[test]
fn child_template_manifest_array_must_not_be_empty() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          slots: {
            realm: { kind: "component" },
          },
          child_templates: {
            worker: {
              manifest: [],
            },
          },
        }
        "#,
    );
    let err = raw.validate().unwrap_err();

    match err {
        Error::InvalidChildTemplate { template, message } => {
            assert_eq!(template, "worker");
            assert!(message.contains("empty array"));
        }
        other => panic!("expected InvalidChildTemplate, got {other:?}"),
    }
}

#[test]
fn child_template_manifest_array_must_not_be_singleton() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          slots: {
            realm: { kind: "component" },
          },
          child_templates: {
            worker: {
              manifest: ["https://example.com/worker.json5"],
            },
          },
        }
        "#,
    );
    let err = raw.validate().unwrap_err();

    match err {
        Error::InvalidChildTemplate { template, message } => {
            assert_eq!(template, "worker");
            assert!(message.contains("at least two"));
        }
        other => panic!("expected InvalidChildTemplate, got {other:?}"),
    }
}
