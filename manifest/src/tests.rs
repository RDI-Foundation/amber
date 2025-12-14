use super::*;

#[test]
fn interpolation_parsing_splits_parts() {
    let parsed: InterpolatedString = "a ${config.b} c".parse().unwrap();
    assert_eq!(
        parsed.parts,
        vec![
            InterpolatedPart::Literal("a ".to_string()),
            InterpolatedPart::Interpolation {
                source: InterpolationSource::Config,
                query: "b".to_string()
            },
            InterpolatedPart::Literal(" c".to_string()),
        ]
    );
}

#[test]
fn interpolation_without_placeholders_is_literal() {
    let parsed: InterpolatedString = "hello".parse().unwrap();
    assert_eq!(
        parsed.parts,
        vec![InterpolatedPart::Literal("hello".to_string())]
    );
}

#[test]
fn interpolation_multiple_and_adjacent() {
    let parsed: InterpolatedString = "${config.a}${slots.llm.url}".parse().unwrap();
    assert_eq!(
        parsed.parts,
        vec![
            InterpolatedPart::Interpolation {
                source: InterpolationSource::Config,
                query: "a".to_string()
            },
            InterpolatedPart::Interpolation {
                source: InterpolationSource::Slots,
                query: "llm.url".to_string()
            },
        ]
    );
}

#[test]
fn interpolation_unknown_source_errors() {
    assert!("${foo.bar}".parse::<InterpolatedString>().is_err());
}

#[test]
fn interpolation_missing_closing_brace_errors() {
    assert!("x ${config.a".parse::<InterpolatedString>().is_err());
}

#[test]
fn program_args_string_sugar_splits() {
    let m: Manifest = r#"
        {
          manifest_version: "1.0.0",
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
    let m: Manifest = r#"
        {
          manifest_version: "1.0.0",
          bindings: [
            { target_component: "a", target_slot: "s", source_component: "b", source_capability: "c" },
            { target: "a.s", source: "b.c" },
          ],
        }
        "#
    .parse()
    .unwrap();

    let expected = BTreeSet::from([
        Binding {
            target_component: "a".to_string(),
            target_slot: "s".to_string(),
            source_component: "b".to_string(),
            source_capability: "c".to_string(),
        },
        Binding {
            target_component: "a".to_string(),
            target_slot: "s".to_string(),
            source_component: "b".to_string(),
            source_capability: "c".to_string(),
        },
    ]);

    assert_eq!(m.bindings, expected);
}

#[test]
fn binding_missing_source_capability_errors() {
    let err = r#"
        {
          manifest_version: "1.0.0",
          bindings: [
            { target_component: "a", target_slot: "s", source_component: "b" }
          ],
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    assert!(
        err.to_string()
            .contains("binding missing `source_capability`")
    );
}

#[test]
fn manifest_deserialize_error_includes_path() {
    let err = r#"
        {
          manifest_version: "1.0.0",
          program: {
            image: "x",
            network: { endpoints: [ { name: "endpoint", port: "80" } ] }
          }
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    match err {
        ValidationError::Json5Path(err) => {
            assert_eq!(err.path().to_string(), "program.network.endpoints[0].port");
        }
        other => panic!("expected Json5Path error, got: {other}"),
    }
}

#[test]
fn components_sugar_parses() {
    let m: Manifest = r##"
        {
          manifest_version: "1.0.0",
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
fn manifest_ref_canonical_form_with_digest_parses() {
    let m: Manifest = r##"
        {
          manifest_version: "1.0.0",
          components: {
            a: {
              url: "https://example.com/amber/pkg/v1",
              digest: "sha384:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
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
            assert_eq!(digest.alg, HashAlg::Sha384);
            assert_eq!(digest.hash, [0u8; 48]);
        }
        _ => panic!("expected reference"),
    }
}

#[test]
fn manifest_ref_invalid_digest_errors() {
    let err = r##"
        {
          manifest_version: "1.0.0",
          components: {
            a: { url: "https://example.com/amber/pkg/v1", digest: "sha384:not_base64" }
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
fn endpoint_validation_fails_for_unknown_reference() {
    let err = r#"
        {
          manifest_version: "1.0.0",
          program: {
            image: "x",
            network: { endpoints: [ { name: "endpoint", port: 80 } ] }
          },
          provides: {
            api: { kind: "http", endpoint: "missing" }
          }
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    assert!(err.to_string().contains("unknown endpoint `missing`"));
}

#[test]
fn endpoint_validation_passes_for_defined_reference() {
    let m: Manifest = r#"
        {
          manifest_version: "1.0.0",
          program: {
            image: "x",
            network: { endpoints: [ { name: "endpoint", port: 80 } ] }
          },
          provides: {
            api: { kind: "http", endpoint: "endpoint" }
          }
        }
        "#
    .parse()
    .unwrap();

    let _ = m;
}

#[test]
fn duplicate_keys_in_components_map_errors() {
    let res: Result<Manifest, _> = r##"
        {
          manifest_version: "1.0.0",
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
          manifest_version: "1.0.0",
          program: {
            image: "x",
            env: { FOO: "a", FOO: "b" }
          }
        }
        "#
    .parse();

    assert!(res.is_err());
}
