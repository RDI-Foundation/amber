use std::sync::Arc;

use amber_manifest::{
    CapabilityDecl, CapabilityKind, ComponentDecl, Endpoint, Error, InterpolatedString, Manifest,
    ManifestRef, ManifestUrl, Network, Program, ProgramArgs, ProvideDecl,
};
use bon::{map, set};
use semver::Version;
use serde_json::json;

#[test]
fn manifest_builder_constructs_a_valid_manifest() {
    let program = Program::builder()
        .image("example:latest")
        .args(ProgramArgs(vec![
            "/bin/true".parse::<InterpolatedString>().unwrap(),
        ]))
        .network(
            Network::builder()
                .endpoints(set![Endpoint::builder().name("api").port(80).build()])
                .build(),
        )
        .build();

    let provides = map! {
        "http": ProvideDecl::builder()
            .decl(CapabilityDecl::builder().kind(CapabilityKind::Http).build())
            .endpoint("api")
            .build(),
    };

    let manifest = Manifest::builder()
        .program(program)
        .provides(provides)
        .build()
        .expect("builder should produce a valid manifest");

    assert_eq!(manifest.manifest_version(), &Version::new(0, 1, 0));
    assert_eq!(manifest.provides().len(), 1);
}

#[test]
fn manifest_builder_rejects_invalid_manifest_missing_provide_endpoint() {
    let provides = map! {
        "http": ProvideDecl::builder()
            .decl(CapabilityDecl::builder().kind(CapabilityKind::Http).build())
            .build(),
    };

    let err = Manifest::builder().provides(provides).build().unwrap_err();

    assert!(matches!(err, Error::MissingProvideEndpoint { .. }));
}

#[test]
fn manifest_builder_rejects_invalid_config_schema() {
    let bad_schema = json!({
        "type": "object",
        "properties": {
            "__bad": { "type": "string" }
        }
    });

    let err = Manifest::builder()
        .config_schema(bad_schema)
        .build()
        .unwrap_err();

    assert!(matches!(err, Error::InvalidConfigSchema(_)));
}

#[test]
fn raw_validate_rejects_invalid_manifest_refs_even_if_mutated_programmatically() {
    let mut r: ManifestRef = "https://example.com/manifest.json".parse().unwrap();

    r.url = ManifestUrl::Relative(Arc::from(""));

    let components = map! {
        "child": ComponentDecl::Reference(r)
    };

    let err = Manifest::builder()
        .components(components)
        .build()
        .unwrap_err();

    assert!(matches!(err, Error::InvalidManifestRef(_)));
}
