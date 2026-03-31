use super::*;

#[test]
fn mounts_parse_config_sources_for_plain_and_secret_paths() {
    let m: Manifest = r#"
        {
          manifest_version: "0.1.0",
          config_schema: {
            type: "object",
            properties: {
              app: { type: "string" },
              token: { type: "string", secret: true },
            },
            required: ["app", "token"],
          },
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/run/app.txt", from: "config.app" },
              { path: "/run/token.txt", from: "config.token" },
            ]
          }
        }
        "#
    .parse()
    .unwrap();

    let program = m.program.as_ref().expect("program");
    assert_eq!(program.mounts().len(), 2);
}

#[test]
fn storage_mount_source_parses_for_storage_slots() {
    let manifest: Manifest = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/var/lib/app", from: "slots.state" },
            ]
          },
          slots: {
            state: { kind: "storage" },
          },
        }
        "#
    .parse()
    .unwrap();

    let program = manifest.program.as_ref().expect("program");
    assert_eq!(program.mounts().len(), 1);
    assert_eq!(program.mounts()[0].source.to_string(), "slots.state");
}

#[test]
fn storage_mount_source_parses_for_local_resources() {
    let manifest: Manifest = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/var/lib/app", from: "resources.state" },
            ]
          },
          resources: {
            state: { kind: "storage" },
          },
        }
        "#
    .parse()
    .unwrap();

    let program = manifest.program.as_ref().expect("program");
    assert_eq!(program.mounts().len(), 1);
    assert_eq!(program.mounts()[0].source.to_string(), "resources.state");
}

#[test]
fn storage_resource_parses_without_source() {
    let manifest: Manifest = r#"
        {
          manifest_version: "0.1.0",
          resources: {
            state: { kind: "storage" },
          },
        }
        "#
    .parse()
    .unwrap();

    let resource = manifest.resources().get("state").expect("resource");
    assert_eq!(resource.kind, CapabilityKind::Storage);
}

#[test]
fn storage_resource_param_parses_interpolation() {
    let manifest: Manifest = r#"
        {
          manifest_version: "0.1.0",
          resources: {
            state: {
              kind: "storage",
              params: { size: "${config.storage_size}" },
            },
          },
        }
        "#
    .parse()
    .unwrap();

    let resource = manifest.resources().get("state").expect("resource");
    assert_eq!(
        resource
            .params
            .size
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        Some("${config.storage_size}")
    );
}

#[test]
fn storage_mount_rejects_unknown_slot() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/var/lib/app", from: "slots.state" },
            ]
          }
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    match err {
        Error::UnknownMountSlot { slot } => assert_eq!(slot, "state"),
        other => panic!("expected UnknownMountSlot error, got: {other}"),
    }
}

#[test]
fn storage_mount_rejects_unknown_resource() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/var/lib/app", from: "resources.state" },
            ]
          }
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    match err {
        Error::UnknownMountResource { resource } => assert_eq!(resource, "state"),
        other => panic!("expected UnknownMountResource error, got: {other}"),
    }
}

#[test]
fn storage_mount_rejects_non_storage_slot() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/var/lib/app", from: "slots.api" },
            ]
          },
          slots: {
            api: { kind: "http" },
          },
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    match err {
        Error::MountSlotRequiresStorage { slot, kind } => {
            assert_eq!(slot, "api");
            assert_eq!(kind, CapabilityKind::Http);
        }
        other => panic!("expected MountSlotRequiresStorage error, got: {other}"),
    }
}

#[test]
fn storage_provide_is_rejected() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
          },
          provides: {
            state: { kind: "storage", endpoint: "ignored" },
          },
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    match err {
        Error::UnsupportedProvideKind { name, kind } => {
            assert_eq!(name, "state");
            assert_eq!(kind, CapabilityKind::Storage);
        }
        other => panic!("expected UnsupportedProvideKind error, got: {other}"),
    }
}

#[test]
fn framework_docker_mount_requires_experimental_feature() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/var/run/docker.sock", from: "framework.docker" },
            ]
          }
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

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
fn framework_docker_mount_is_allowed_with_experimental_feature() {
    let m: Manifest = r#"
        {
          manifest_version: "0.1.0",
          experimental_features: ["docker"],
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/var/run/docker.sock", from: "framework.docker" },
            ]
          }
        }
        "#
    .parse()
    .unwrap();

    let program = m.program.as_ref().expect("program");
    assert_eq!(program.mounts().len(), 1);
    assert_eq!(program.mounts()[0].source.to_string(), "framework.docker");
}

#[test]
fn config_mount_accepts_secret_path() {
    let manifest: Manifest = r#"
        {
          manifest_version: "0.1.0",
          config_schema: {
            type: "object",
            properties: {
              token: { type: "string", secret: true },
            },
          },
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/run/token.txt", from: "config.token" },
            ]
          }
        }
        "#
    .parse()
    .unwrap();

    assert_eq!(
        manifest.program.as_ref().expect("program").mounts().len(),
        1
    );
}

#[test]
fn secret_mount_source_is_rejected() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          config_schema: {
            type: "object",
            properties: {
              token: { type: "string" },
            },
          },
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/run/token.txt", from: "secret.token" },
            ]
          }
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    assert!(err.to_string().contains("invalid mount source"));
    assert!(err.to_string().contains("unknown mount source"));
}

#[test]
fn duplicate_mount_paths_error() {
    let err = r#"
        {
          manifest_version: "0.1.0",
          config_schema: {
            type: "object",
            properties: {
              app: { type: "string" },
            },
          },
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/run/app.txt", from: "config.app" },
              { path: "/run/app.txt", from: "config.app" },
            ]
          }
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    assert!(err.to_string().contains("duplicate mount path"));
}

#[test]
fn conditional_mounts_still_validate_storage_sources() {
    let err = r#"
        {
          manifest_version: "0.3.0",
          config_schema: {
            type: "object",
            properties: {
              enabled: { type: "boolean" },
            },
          },
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { when: "config.enabled", path: "/var/lib/app", from: "slots.state" },
            ]
          }
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    match err {
        Error::UnknownMountSlot { slot } => assert_eq!(slot, "state"),
        other => panic!("expected UnknownMountSlot error, got: {other}"),
    }
}

#[test]
fn interpolated_mount_paths_still_validate_literal_storage_sources() {
    let err = r#"
        {
          manifest_version: "0.3.0",
          config_schema: {
            type: "object",
            properties: {
              filename: { type: "string" },
            },
          },
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/var/${config.filename}", from: "slots.state" },
            ]
          }
        }
        "#
    .parse::<Manifest>()
    .unwrap_err();

    match err {
        Error::UnknownMountSlot { slot } => assert_eq!(slot, "state"),
        other => panic!("expected UnknownMountSlot error, got: {other}"),
    }
}

#[test]
fn interpolated_non_file_mount_sources_are_preserved_for_link_time_resolution() {
    let manifest = r#"
        {
          manifest_version: "0.3.0",
          config_schema: {
            type: "object",
            properties: {
              source_kind: { type: "string" },
            },
          },
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/var/lib/app", from: "resources.${config.source_kind}" },
            ]
          }
        }
        "#
    .parse::<Manifest>()
    .expect("manifest");

    assert_eq!(
        manifest.program().expect("program").mounts()[0]
            .source
            .to_string(),
        "resources.${config.source_kind}"
    );
}

#[test]
fn fully_dynamic_mount_sources_are_preserved_for_link_time_resolution() {
    let manifest = r#"
        {
          manifest_version: "0.3.0",
          config_schema: {
            type: "object",
            properties: {
              mount_source: { type: "string" },
            },
          },
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/var/lib/app", from: "${config.mount_source}" },
            ]
          }
        }
        "#
    .parse::<Manifest>()
    .expect("manifest");

    assert_eq!(
        manifest.program().expect("program").mounts()[0]
            .source
            .to_string(),
        "${config.mount_source}"
    );
}
