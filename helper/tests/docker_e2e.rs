use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use amber_template::{ConfigTemplatePayload, ProgramTemplateSpec, TemplatePart, TemplateSpec};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::json;
use tempfile::tempdir;

const ROOT_SCHEMA_ENV: &str = "AMBER_ROOT_CONFIG_SCHEMA_B64";
const COMPONENT_SCHEMA_ENV: &str = "AMBER_COMPONENT_CONFIG_SCHEMA_B64";
const COMPONENT_TEMPLATE_ENV: &str = "AMBER_COMPONENT_CONFIG_TEMPLATE_B64";
const TEMPLATE_SPEC_ENV: &str = "AMBER_TEMPLATE_SPEC_B64";

fn encode_json_b64(value: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(value).expect("json should serialize");
    STANDARD.encode(bytes)
}

fn encode_spec_b64(spec: &TemplateSpec) -> String {
    let bytes = serde_json::to_vec(spec).expect("spec should serialize");
    STANDARD.encode(bytes)
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("helper crate should live under the workspace root")
        .to_path_buf()
}

fn use_prebuilt_images() -> bool {
    std::env::var("AMBER_TEST_USE_PREBUILT_IMAGES").is_ok()
}

fn image_exists(tag: &str) -> bool {
    Command::new("docker")
        .arg("image")
        .arg("inspect")
        .arg(tag)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn docker_target_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => panic!("unsupported host arch for docker build: {other}"),
    }
}

fn build_helper_image(tag: &str) {
    if use_prebuilt_images() {
        assert!(
            image_exists(tag),
            "AMBER_TEST_USE_PREBUILT_IMAGES is set but {tag} is not available locally. Ensure the \
             image is pulled and tagged before running tests."
        );
        return;
    }
    let root = workspace_root();
    let dockerfile = root.join("docker/amber-helper/Dockerfile");
    let status = Command::new("docker")
        .arg("build")
        .arg("--build-arg")
        .arg(format!("TARGETARCH={}", docker_target_arch()))
        .arg("-t")
        .arg(tag)
        .arg("-f")
        .arg(dockerfile)
        .arg(root)
        .status()
        .expect("docker build should start");
    assert!(status.success(), "docker build failed for {tag}");
}

fn run_helper_container(image: &str, out_dir: &Path, envs: &[(String, String)]) -> Output {
    let mut cmd = Command::new("docker");
    cmd.arg("run")
        .arg("--rm")
        .arg("-v")
        .arg(format!("{}:/out", out_dir.display()));
    for (key, value) in envs {
        cmd.arg("-e").arg(format!("{key}={value}"));
    }
    cmd.arg(image).arg("run");
    cmd.output().expect("docker run should start")
}

#[test]
#[ignore = "requires docker; run manually or in CI"]
fn helper_image_executes_run_plan_in_scratch() {
    let tag = "amber-helper:e2e";
    build_helper_image(tag);

    let out_dir = tempdir().expect("temp dir should create");
    let dest = "/out/amber-helper-installed";

    let root_schema = json!({
        "type": "object",
        "properties": {
            "dest": { "type": "string" }
        },
        "required": ["dest"],
        "additionalProperties": false
    });
    let component_schema = root_schema.clone();

    let template_spec = TemplateSpec {
        program: ProgramTemplateSpec {
            entrypoint: vec![
                vec![TemplatePart::lit("/amber-helper")],
                vec![TemplatePart::lit("install")],
                vec![TemplatePart::config("dest")],
            ],
            env: BTreeMap::new(),
        },
    };

    let envs = vec![
        (ROOT_SCHEMA_ENV.to_string(), encode_json_b64(&root_schema)),
        (
            COMPONENT_SCHEMA_ENV.to_string(),
            encode_json_b64(&component_schema),
        ),
        (
            COMPONENT_TEMPLATE_ENV.to_string(),
            encode_json_b64(&ConfigTemplatePayload::Root.to_value()),
        ),
        (
            TEMPLATE_SPEC_ENV.to_string(),
            encode_spec_b64(&template_spec),
        ),
        ("AMBER_CONFIG_DEST".to_string(), dest.to_string()),
    ];

    let output = run_helper_container(tag, out_dir.path(), &envs);
    assert!(
        output.status.success(),
        "docker run failed (status: {})\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let installed = out_dir.path().join("amber-helper-installed");
    let metadata = fs::metadata(&installed).expect("installed helper should exist");
    assert!(metadata.len() > 0, "installed helper is empty");
}
