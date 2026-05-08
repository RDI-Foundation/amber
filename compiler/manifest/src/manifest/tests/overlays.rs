use super::*;

#[test]
fn use_entries_and_overlays_parse() {
    let manifest: Manifest = r##"
        {
          manifest_version: "0.4.0",
          use: {
            wrapper: "https://example.com/wrapper.json5",
            membrane: { manifest: "https://example.com/membrane.json5", config: { level: "info" } },
          },
          overlays: ["#wrapper.rewrite", "#membrane.apply"],
        }
        "##
    .parse()
    .unwrap();

    assert_eq!(manifest.uses().len(), 2);
    assert_eq!(manifest.overlays().len(), 2);
    assert_eq!(manifest.overlays()[0].overlay.alias, "wrapper");
    assert_eq!(manifest.overlays()[0].overlay.export, "rewrite");
    assert_eq!(manifest.overlays()[1].overlay.alias, "membrane");
    assert_eq!(manifest.overlays()[1].overlay.export, "apply");
}

#[test]
fn overlay_ref_must_use_hash_alias_export_syntax() {
    let err = r##"
        {
          manifest_version: "0.4.0",
          use: {
            wrapper: "https://example.com/wrapper.json5",
          },
          overlays: ["wrapper.rewrite"],
        }
        "##
    .parse::<Manifest>()
    .unwrap_err();

    assert!(
        err.to_string()
            .contains("invalid overlay ref `wrapper.rewrite`"),
        "expected invalid overlay ref error, got: {err}"
    );
}

#[test]
fn overlay_ref_alias_must_exist_in_use_map() {
    let err = parse_raw(
        r##"
        {
          manifest_version: "0.4.0",
          use: {
            wrapper: "https://example.com/wrapper.json5",
          },
          overlays: ["#missing.rewrite"],
        }
        "##,
    )
    .validate()
    .unwrap_err();

    match err {
        Error::UnknownOverlayUse { alias } => assert_eq!(alias, "missing"),
        other => panic!("expected UnknownOverlayUse error, got: {other}"),
    }
}

#[test]
fn use_requires_manifest_version_0_4_0() {
    let err = parse_raw(
        r#"
        {
          manifest_version: "0.3.0",
          use: {
            wrapper: "https://example.com/wrapper.json5",
          },
        }
        "#,
    )
    .validate()
    .unwrap_err();

    match err {
        Error::UnsupportedManifestFeatureForManifestVersion {
            manifest_version,
            required_version,
            feature,
            pointer,
        } => {
            assert_eq!(*manifest_version, Version::new(0, 3, 0));
            assert_eq!(required_version, "0.4.0");
            assert_eq!(feature, "`use` section");
            assert_eq!(pointer, "/use");
        }
        other => {
            panic!("expected UnsupportedManifestFeatureForManifestVersion error, got: {other}")
        }
    }
}

#[test]
fn overlays_require_manifest_version_0_4_0() {
    let err = parse_raw(
        r##"
        {
          manifest_version: "0.3.0",
          overlays: ["#wrapper.rewrite"],
        }
        "##,
    )
    .validate()
    .unwrap_err();

    match err {
        Error::UnsupportedManifestFeatureForManifestVersion {
            manifest_version,
            required_version,
            feature,
            pointer,
        } => {
            assert_eq!(*manifest_version, Version::new(0, 3, 0));
            assert_eq!(required_version, "0.4.0");
            assert_eq!(feature, "`overlays` section");
            assert_eq!(pointer, "/overlays/0");
        }
        other => {
            panic!("expected UnsupportedManifestFeatureForManifestVersion error, got: {other}")
        }
    }
}

#[test]
fn use_names_must_not_contain_dots() {
    let err = parse_raw(
        r#"
        {
          manifest_version: "0.4.0",
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
          manifest_version: "0.4.0",
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
