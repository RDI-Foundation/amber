use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    thread,
    time::Duration,
};

use amber_config as rc;
use amber_manifest::{
    CapabilityKind, FrameworkCapabilityName, Manifest, ManifestDigest, ManifestRef,
    Program as ManifestProgram, ProvideDecl, SlotDecl,
};
use amber_mesh::{InboundTarget, MeshProvisionOutput, MeshProvisionPlan, MeshProvisionTarget};
use amber_scenario::{
    BindingEdge, BindingFrom, Component, ComponentId, Moniker, ProvideRef, ResourceDecl, Scenario,
    ScenarioExport, SlotRef,
};
use base64::Engine as _;
use serde_json::{Map, Value, json};
use url::Url;

use super::{DockerComposeReporter, *};
use crate::{
    linker::program_lowering::lower_program,
    targets::{mesh::internal_images::resolve_internal_images, storage::StorageIdentity},
};

fn digest(byte: u8) -> ManifestDigest {
    ManifestDigest::new([byte; 32])
}

fn moniker(path: &str) -> Moniker {
    Moniker::from(Arc::from(path))
}

fn internal_images() -> crate::targets::mesh::internal_images::InternalImages {
    resolve_internal_images().expect("internal images should resolve for tests")
}

fn compiled_scenario(output: &crate::CompileOutput) -> crate::reporter::CompiledScenario {
    crate::reporter::CompiledScenario::from_compile_output(output)
        .expect("test compiler output should convert to compiled Scenario")
}

fn render_compose(
    output: &crate::CompileOutput,
) -> Result<super::DockerComposeArtifact, crate::reporter::ReporterError> {
    DockerComposeReporter.emit(&compiled_scenario(output))
}

#[test]
fn render_compose_image_uses_root_default_fallback() {
    let leaves = [rc::SchemaLeaf {
        path: "base_image".to_string(),
        required: true,
        default: Some(json!("ghcr.io/example/default:1")),
        secret: false,
        pointer: "/properties/base_image".to_string(),
    }];
    let root_leaf_by_path: BTreeMap<&str, &rc::SchemaLeaf> = leaves
        .iter()
        .map(|leaf| (leaf.path.as_str(), leaf))
        .collect();

    let rendered = super::render_compose_image(
        &crate::targets::program_config::ProgramImagePlan::RuntimeTemplate(vec![
            crate::targets::program_config::ProgramImagePart::RootConfigPath(
                "base_image".to_string(),
            ),
        ]),
        &root_leaf_by_path,
    )
    .expect("compose image should render");

    assert_eq!(
        rendered,
        "${AMBER_CONFIG_BASE_IMAGE:-ghcr.io/example/default:1}"
    );
}

#[test]
fn render_compose_image_rejects_null_root_default() {
    let leaves = [rc::SchemaLeaf {
        path: "base_image".to_string(),
        required: false,
        default: Some(Value::Null),
        secret: false,
        pointer: "/properties/base_image".to_string(),
    }];
    let root_leaf_by_path: BTreeMap<&str, &rc::SchemaLeaf> = leaves
        .iter()
        .map(|leaf| (leaf.path.as_str(), leaf))
        .collect();

    let err = super::render_compose_image(
        &crate::targets::program_config::ProgramImagePlan::RuntimeTemplate(vec![
            crate::targets::program_config::ProgramImagePart::RootConfigPath(
                "base_image".to_string(),
            ),
        ]),
        &root_leaf_by_path,
    )
    .expect_err("null default should be rejected for runtime image interpolation");

    assert!(
        err.contains("cannot be interpolated into an image string"),
        "{err}"
    );
}

fn compile_output_with_manifest_overrides(
    scenario: Scenario,
    overrides: BTreeMap<ComponentId, Map<String, Value>>,
) -> crate::CompileOutput {
    let url = Url::parse("file:///scenario.json5").expect("test URL should parse");
    let store = crate::DigestStore::new();

    for component in scenario.components.iter().flatten() {
        let mut manifest = serde_json::Map::new();
        manifest.insert(
            "manifest_version".to_string(),
            Value::String("0.1.0".to_string()),
        );
        if let Some(extra) = overrides.get(&component.id) {
            for (key, value) in extra {
                manifest.insert(key.clone(), value.clone());
            }
        }

        let manifest: Manifest = serde_json::from_value(Value::Object(manifest)).unwrap();
        store.put(component.digest, Arc::new(manifest));
    }

    let provenance = crate::Provenance {
        components: scenario
            .components
            .iter()
            .map(|component| {
                let component = component
                    .as_ref()
                    .expect("test scenario component should exist");
                crate::ComponentProvenance {
                    authored_moniker: component.moniker.clone(),
                    declared_ref: ManifestRef::from_url(url.clone()),
                    resolved_url: url.clone(),
                    digest: component.digest,
                    observed_url: None,
                }
            })
            .collect(),
    };

    let config_analysis = crate::config::analysis::ScenarioConfigAnalysis::from_scenario(&scenario)
        .expect("config analysis");
    crate::CompileOutput {
        scenario,
        store,
        provenance,
        diagnostics: Vec::new(),
        config_analysis,
    }
}

fn compile_output(scenario: Scenario) -> crate::CompileOutput {
    compile_output_with_manifest_overrides(scenario, BTreeMap::new())
}

fn lower_test_program(id: usize, value: Value) -> amber_scenario::Program {
    let program: ManifestProgram = serde_json::from_value(value).expect("manifest program");
    lower_program(ComponentId(id), &program, None).expect("program should lower")
}

fn compile_output_with_docker_feature(scenario: Scenario) -> crate::CompileOutput {
    let mut overrides = BTreeMap::new();
    overrides.insert(
        scenario.root,
        Map::from_iter([("experimental_features".to_string(), json!(["docker"]))]),
    );
    compile_output_with_manifest_overrides(scenario, overrides)
}

fn error_contains(err: &crate::Error, needle: &str) -> bool {
    match err {
        crate::Error::Linker(crate::linker::Error::Multiple { errors, .. }) => {
            errors.iter().any(|err| err.to_string().contains(needle))
        }
        crate::Error::Linker(err) => err.to_string().contains(needle),
        other => other.to_string().contains(needle),
    }
}

fn storage_resource_decl(size: Option<&str>) -> ResourceDecl {
    let value = match size {
        Some(size) => json!({
            "kind": "storage",
            "params": { "size": size },
        }),
        None => json!({ "kind": "storage" }),
    };
    serde_json::from_value(value).expect("storage resource decl")
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("compiler crate should live under the workspace root")
        .to_path_buf()
}

fn ensure_amber_cli_binary() -> PathBuf {
    let root = workspace_root();
    let status = Command::new("cargo")
        .current_dir(&root)
        .args(["build", "-q", "-p", "amber-cli"])
        .status()
        .expect("run cargo build -p amber-cli");
    assert!(status.success(), "cargo build -p amber-cli failed");
    root.join("target").join("debug").join("amber")
}

fn use_prebuilt_images() -> bool {
    std::env::var("AMBER_TEST_USE_PREBUILT_IMAGES").is_ok()
}

fn image_platform_opt(tag: &str) -> Option<String> {
    let output = std::process::Command::new("docker")
        .arg("image")
        .arg("inspect")
        .arg("-f")
        .arg("{{.Architecture}}")
        .arg(tag)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let arch = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if arch.is_empty() {
        return None;
    }
    Some(format!("linux/{arch}"))
}

fn image_platform(tag: &str) -> String {
    image_platform_opt(tag).unwrap_or_else(|| {
        panic!("docker image inspect failed for {tag}");
    })
}

fn ensure_image_platform(tag: &str, platform: &str) {
    let needs_pull = match image_platform_opt(tag) {
        Some(existing) => existing != platform,
        None => true,
    };

    if needs_pull {
        let status = std::process::Command::new("docker")
            .arg("pull")
            .arg("--platform")
            .arg(platform)
            .arg(tag)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "docker pull failed for {tag} ({platform})"
        );
    }

    let actual = image_platform(tag);
    assert_eq!(
        actual, platform,
        "image platform mismatch for {tag}: expected {platform}, got {actual}"
    );
}

fn build_docker_image(tag: &str, dockerfile: &Path, context: &Path) -> String {
    // The CI "prebuilt images" smoke job pulls and retags these images ahead of tests.
    // Respecting this flag here avoids rebuilding the same images in every smoke test run.
    if use_prebuilt_images() {
        return image_platform_opt(tag).unwrap_or_else(|| {
            panic!(
                "AMBER_TEST_USE_PREBUILT_IMAGES is set but {tag} is not available locally. Ensure \
                 images are pulled and retagged before running tests."
            )
        });
    }

    let status = std::process::Command::new("docker")
        .arg("buildx")
        .arg("build")
        .arg("--load")
        .arg("-t")
        .arg(tag)
        .arg("-f")
        .arg(dockerfile)
        .arg(context)
        .status()
        .unwrap();
    assert!(status.success(), "docker build failed for {tag}");
    image_platform(tag)
}

fn build_helper_image() -> String {
    let root = workspace_root();
    let images = internal_images();
    build_docker_image(
        &images.helper,
        &root.join("docker/amber-helper/Dockerfile"),
        &root,
    )
}

fn build_router_image() -> String {
    let root = workspace_root();
    let images = internal_images();
    build_docker_image(
        &images.router,
        &root.join("docker/amber-router/Dockerfile"),
        &root,
    )
}

fn build_provisioner_image() -> String {
    let root = workspace_root();
    let images = internal_images();
    build_docker_image(
        &images.provisioner,
        &root.join("docker/amber-provisioner/Dockerfile"),
        &root,
    )
}

fn require_same_platform(images: &[(&str, String)]) -> String {
    let (first_tag, first_platform) = images
        .first()
        .expect("at least one image platform should be provided");
    for (tag, platform) in images.iter().skip(1) {
        assert_eq!(
            platform, first_platform,
            "image platform mismatch: {first_tag} is {first_platform}, {tag} is {platform}"
        );
    }
    first_platform.clone()
}

fn parse_compose(artifact: &super::DockerComposeArtifact) -> super::DockerComposeFile {
    serde_yaml::from_str(artifact.compose_yaml()).expect("compose yaml should parse")
}

fn service<'a>(compose: &'a super::DockerComposeFile, name: &str) -> &'a super::Service {
    compose
        .services
        .get(name)
        .unwrap_or_else(|| panic!("service {name} missing"))
}

fn env_value(service: &super::Service, key: &str) -> Option<String> {
    let env = service.environment.as_ref()?;
    match env {
        super::Environment::Map(map) => map.get(key).cloned(),
        super::Environment::List(list) => {
            let prefix = format!("{key}=");
            list.iter().find_map(|entry| {
                if entry == key {
                    Some(String::new())
                } else {
                    entry.strip_prefix(&prefix).map(|v| v.to_string())
                }
            })
        }
    }
}

fn assert_service_hardened(service: &super::Service, yaml: &str) {
    assert!(service.cap_drop.iter().any(|cap| cap == "ALL"), "{yaml}");
    assert!(
        service
            .security_opt
            .iter()
            .any(|opt| opt == "no-new-privileges:true"),
        "{yaml}"
    );
}

fn assert_internal_service_rootfs_hardened(service: &super::Service, yaml: &str) {
    assert_eq!(service.read_only, Some(true), "{yaml}");
}

fn injected_docker_gateway_service(compose: &super::DockerComposeFile) -> (&str, &super::Service) {
    compose
        .services
        .iter()
        .find_map(|(name, svc)| {
            env_value(svc, super::DOCKER_GATEWAY_CONFIG_ENV)
                .is_some()
                .then_some((name.as_str(), svc))
        })
        .expect("injected docker gateway service missing")
}

fn assert_depends_on(service: &super::Service, name: &str, condition: &str) {
    let depends_on = service
        .depends_on
        .as_ref()
        .unwrap_or_else(|| panic!("depends_on missing for dependency {name}"));
    match depends_on {
        super::DependsOn::List(deps) => {
            assert_eq!(
                condition, "service_started",
                "list-style depends_on only supports service_started"
            );
            assert!(
                deps.iter().any(|dep| dep == name),
                "dependency {name} missing from depends_on list"
            );
        }
        super::DependsOn::Conditions(deps) => {
            let actual = deps
                .get(name)
                .unwrap_or_else(|| panic!("dependency {name} missing from depends_on map"));
            assert_eq!(actual.condition, condition);
        }
    }
}

fn storage_scenario(version: &str, initial_state: &str) -> Scenario {
    let provide_http: ProvideDecl =
        serde_json::from_value(json!({ "kind": "http", "endpoint": "http" })).unwrap();

    let root = Component {
        id: ComponentId(0),
        parent: None,
        moniker: moniker("/"),
        digest: digest(0),
        config: None,
        config_schema: None,
        program: Some(lower_test_program(
            0,
            json!({
                "image": "busybox:1.36.1",
                "entrypoint": [
                    "sh",
                    "-eu",
                    "-c",
                    format!(
                        "mkdir -p /var/lib/app /tmp/www\nif [ ! -f /var/lib/app/state.txt ]; then printf '%s\\n' '{initial_state}' >/var/lib/app/state.txt; fi\nprintf '%s\\n' '{version}' >/tmp/www/version.txt\ncp /var/lib/app/state.txt /tmp/www/state.txt\nexec httpd -f -p 8080 -h /tmp/www"
                    )
                ],
                "mounts": [
                    { "path": "/var/lib/app", "from": "resources.state" }
                ],
                "network": {
                    "endpoints": [
                        { "name": "http", "port": 8080, "protocol": "http" }
                    ]
                }
            }),
        )),
        slots: BTreeMap::new(),
        provides: BTreeMap::from([("http".to_string(), provide_http.clone())]),
        resources: BTreeMap::from([("state".to_string(), storage_resource_decl(None))]),
        metadata: None,
        child_templates: BTreeMap::new(),
        children: Vec::new(),
    };

    Scenario {
        manifest_catalog: BTreeMap::new(),
        root: ComponentId(0),
        components: vec![Some(root)],
        bindings: Vec::new(),
        exports: vec![ScenarioExport {
            name: "http".to_string(),
            capability: provide_http.decl.clone(),
            from: ProvideRef {
                component: ComponentId(0),
                name: "http".to_string(),
            },
        }],
    }
}

mod policy;
mod rendering;
use self::rendering::provision_plan;

mod smoke;
