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
fn child_template_requires_exactly_one_manifest_source() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          slots: {
            realm: { kind: "component" },
          },
          child_templates: {
            worker: {
              manifest: "https://example.com/worker.json5",
              allowed_manifests: [
                "https://example.com/other.json5",
              ],
            },
          },
        }
        "#,
    );
    let err = raw.validate().unwrap_err();

    match err {
        Error::InvalidChildTemplate { template, message } => {
            assert_eq!(template, "worker");
            assert!(message.contains("exactly one"));
        }
        other => panic!("expected InvalidChildTemplate, got {other:?}"),
    }
}

#[test]
fn child_template_allowed_manifests_must_be_non_empty() {
    let raw = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          slots: {
            realm: { kind: "component" },
          },
          child_templates: {
            worker: {
              allowed_manifests: [],
            },
          },
        }
        "#,
    );
    let err = raw.validate().unwrap_err();

    match err {
        Error::InvalidChildTemplate { template, message } => {
            assert_eq!(template, "worker");
            assert!(message.contains("must not be empty"));
        }
        other => panic!("expected InvalidChildTemplate, got {other:?}"),
    }
}
