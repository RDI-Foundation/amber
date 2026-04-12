use super::*;

#[test]
fn use_entries_and_policies_parse() {
    let manifest: Manifest = r##"
        {
          manifest_version: "0.1.0",
          experimental_features: ["governance"],
          use: {
            wrapper: "https://example.com/wrapper.json5",
            membrane: { manifest: "https://example.com/membrane.json5", config: { level: "info" } },
          },
          policies: ["#wrapper.rewrite", "#membrane.apply"],
        }
        "##
    .parse()
    .unwrap();

    assert_eq!(manifest.uses().len(), 2);
    assert_eq!(manifest.policies().len(), 2);
    assert_eq!(manifest.policies()[0].alias, "wrapper");
    assert_eq!(manifest.policies()[0].export, "rewrite");
    assert_eq!(manifest.policies()[1].alias, "membrane");
    assert_eq!(manifest.policies()[1].export, "apply");
}

#[test]
fn policy_ref_must_use_hash_alias_export_syntax() {
    let err = r##"
        {
          manifest_version: "0.1.0",
          experimental_features: ["governance"],
          use: {
            wrapper: "https://example.com/wrapper.json5",
          },
          policies: ["wrapper.rewrite"],
        }
        "##
    .parse::<Manifest>()
    .unwrap_err();

    assert!(
        err.to_string()
            .contains("invalid policy ref `wrapper.rewrite`"),
        "expected invalid policy ref error, got: {err}"
    );
}

#[test]
fn policy_ref_alias_must_exist_in_use_map() {
    let err = parse_raw(
        r##"
        {
          manifest_version: "0.1.0",
          experimental_features: ["governance"],
          use: {
            wrapper: "https://example.com/wrapper.json5",
          },
          policies: ["#missing.rewrite"],
        }
        "##,
    )
    .validate()
    .unwrap_err();

    match err {
        Error::UnknownPolicyUse { alias } => assert_eq!(alias, "missing"),
        other => panic!("expected UnknownPolicyUse error, got: {other}"),
    }
}

#[test]
fn use_requires_policies_experimental_feature() {
    let err = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          use: {
            wrapper: "https://example.com/wrapper.json5",
          },
        }
        "#,
    )
    .validate()
    .unwrap_err();

    match err {
        Error::SectionRequiresFeature { section, feature } => {
            assert_eq!(section, "use");
            assert_eq!(feature, "governance");
        }
        other => panic!("expected SectionRequiresFeature error, got: {other}"),
    }
}

#[test]
fn policies_require_policies_experimental_feature() {
    let err = parse_raw(
        r##"
        {
          manifest_version: "0.1.0",
          policies: ["#wrapper.rewrite"],
        }
        "##,
    )
    .validate()
    .unwrap_err();

    match err {
        Error::SectionRequiresFeature { section, feature } => {
            assert_eq!(section, "policies");
            assert_eq!(feature, "governance");
        }
        other => panic!("expected SectionRequiresFeature error, got: {other}"),
    }
}

#[test]
fn use_names_must_not_contain_dots() {
    let err = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          experimental_features: ["governance"],
          use: {
            "wrap.per": "https://example.com/wrapper.json5",
          },
        }
        "#,
    )
    .validate()
    .unwrap_err();

    match err {
        Error::InvalidName { kind, name } => {
            assert_eq!(kind, "use");
            assert_eq!(name, "wrap.per");
        }
        other => panic!("expected InvalidName error, got: {other}"),
    }
}

#[test]
fn use_environment_reference_must_exist() {
    let err = parse_raw(
        r#"
        {
          manifest_version: "0.1.0",
          experimental_features: ["governance"],
          use: {
            wrapper: {
              manifest: "https://example.com/wrapper.json5",
              environment: "missing",
            },
          },
          environments: {
            present: { resolvers: ["x"] },
          },
        }
        "#,
    )
    .validate()
    .unwrap_err();

    match err {
        Error::UnknownUseEnvironment { name, environment } => {
            assert_eq!(name, "wrapper");
            assert_eq!(environment, "missing");
        }
        other => panic!("expected UnknownUseEnvironment error, got: {other}"),
    }
}
