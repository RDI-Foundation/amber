use super::*;

#[test]
fn create_empty_manifest() {
    Manifest::empty();
}

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
    let m: Manifest = r##"
        {
          manifest_version: "1.0.0",
          bindings: [
            { to: "#a", slot: "s", from: "#b", capability: "c" },
            { to: "#a.s", from: "#b.c" },
            { to: "#a", slot: "s", from: "self", capability: "d" },
            { to: "#a.s", from: "self.d" },
          ],
        }
        "##
    .parse()
    .unwrap();

    let expected = BTreeSet::from([
        Binding {
            to: "#a".to_string(),
            slot: "s".to_string(),
            from: "#b".to_string(),
            capability: "c".to_string(),
            weak: false,
        },
        Binding {
            to: "#a".to_string(),
            slot: "s".to_string(),
            from: "self".to_string(),
            capability: "d".to_string(),
            weak: false,
        },
    ]);

    assert_eq!(m.bindings, expected);
}

#[test]
fn binding_component_refs_require_hash_for_children() {
    let err = r#"
        {
          manifest_version: "1.0.0",
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
fn binding_missing_capability_errors() {
    let err = r#"
        {
          manifest_version: "1.0.0",
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
fn binding_round_trip_through_canonical_json_parses() {
    let m: Manifest = r##"
        {
          manifest_version: "1.0.0",
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
        Error::Json5Path(err) => {
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
            match digest {
                ManifestDigest::Sha256(bytes) => assert_eq!(bytes, &[0u8; 32]),
            }
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
