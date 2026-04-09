use super::*;

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
          experimental_features: ["docker", "policies"],
        }
        "#
    .parse()
    .unwrap();

    assert!(
        manifest
            .experimental_features()
            .contains(&ExperimentalFeature::Docker)
    );
    assert!(
        manifest
            .experimental_features()
            .contains(&ExperimentalFeature::Policies)
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
