#![cfg(target_os = "linux")]

#[path = "test_support/outputs_root.rs"]
mod outputs_root_support;
#[path = "test_support/target_dir.rs"]
mod target_dir_support;
#[path = "test_support/workspace_root.rs"]
mod workspace_root_support;

use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use amber_images::{AMBER_HELPER, AMBER_PROVISIONER, AMBER_ROUTER};
use outputs_root_support::cli_test_outputs_root;
use target_dir_support::cargo_target_dir;
use workspace_root_support::workspace_root;

const IMAGE_NAME: &str = "amber-example-kvm-checker";
const COMPOSE_PROJECT: &str = "kvm-smoke";

fn progress(message: impl AsRef<str>) {
    eprintln!("[kvm_smoke] {}", message.as_ref());
}

fn kvm_gid() -> Option<u32> {
    fs::metadata("/dev/kvm").ok().map(|m| m.gid())
}

fn ensure_runtime_binaries_built(workspace_root: &Path) -> PathBuf {
    progress(format!(
        "building amber runtime binaries in {}",
        workspace_root.display()
    ));
    let output = Command::new("cargo")
        .current_dir(workspace_root)
        .arg("build")
        .arg("-q")
        .arg("-p")
        .arg("amber-cli")
        .output()
        .expect("failed to build runtime binaries for kvm smoke test");
    if !output.status.success() {
        panic!(
            "failed to build kvm runtime binaries\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    progress("finished building amber runtime binaries");
    cargo_target_dir(workspace_root).join("debug")
}

fn build_checker_image(workspace_root: &Path) {
    progress(format!("building Docker image {IMAGE_NAME}"));
    let output = Command::new("docker")
        .arg("build")
        .arg("-t")
        .arg(IMAGE_NAME)
        .arg(workspace_root.join("examples").join("framework-kvm"))
        .output()
        .expect("failed to run docker build");
    if !output.status.success() {
        panic!(
            "docker build failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    progress("finished building Docker image");
}

fn ensure_internal_images(workspace_root: &Path) {
    build_internal_image_if_needed(
        AMBER_HELPER.reference,
        &workspace_root.join("docker/amber-helper/Dockerfile"),
    );
    build_internal_image_if_needed(
        AMBER_PROVISIONER.reference,
        &workspace_root.join("docker/amber-provisioner/Dockerfile"),
    );
    build_internal_image_if_needed(
        AMBER_ROUTER.reference,
        &workspace_root.join("docker/amber-router/Dockerfile"),
    );
}

fn build_internal_image_if_needed(tag: &str, dockerfile: &Path) {
    if docker_image_exists(tag) {
        return;
    }

    progress(format!("building internal image {tag}"));
    let output = Command::new("docker")
        .arg("buildx")
        .arg("build")
        .arg("--load")
        .arg("-t")
        .arg(tag)
        .arg("-f")
        .arg(dockerfile)
        .arg(workspace_root())
        .output()
        .expect("failed to run docker buildx build");
    if !output.status.success() {
        panic!(
            "docker buildx build failed for {tag}\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

fn docker_image_exists(tag: &str) -> bool {
    Command::new("docker")
        .arg("image")
        .arg("inspect")
        .arg(tag)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn compile_docker_compose_or_panic(amber: &Path, output_dir: &Path, manifest_path: &Path) {
    progress(format!(
        "compiling docker compose output from {} into {}",
        manifest_path.display(),
        output_dir.display()
    ));
    let output = Command::new(amber)
        .arg("compile")
        .arg("--docker-compose")
        .arg(output_dir)
        .arg(manifest_path)
        .output()
        .expect("failed to run amber compile --docker-compose");
    if !output.status.success() {
        panic!(
            "amber compile --docker-compose failed\nmanifest: {}\nstatus: \
             {}\nstdout:\n{}\nstderr:\n{}",
            manifest_path.display(),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    progress(format!(
        "finished compiling docker compose output from {}",
        manifest_path.display()
    ));
}

fn docker_compose_up_or_panic(compose_file: &Path, kvm_gid: u32) {
    progress("running docker compose up");
    let output = Command::new("docker")
        .arg("compose")
        .arg("-f")
        .arg(compose_file)
        .arg("-p")
        .arg(COMPOSE_PROJECT)
        .arg("up")
        .arg("--attach")
        .arg("c1-checker")
        .arg("--abort-on-container-exit")
        .arg("--exit-code-from")
        .arg("c1-checker")
        .env("AMBER_KVM_GID", kvm_gid.to_string())
        .output()
        .expect("failed to run docker compose up");
    if !output.status.success() {
        panic!(
            "c1-checker exited with status {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    progress("c1-checker completed successfully");
}

fn docker_compose_down(compose_file: &Path, kvm_gid: u32) {
    let output = Command::new("docker")
        .arg("compose")
        .arg("-f")
        .arg(compose_file)
        .arg("-p")
        .arg(COMPOSE_PROJECT)
        .arg("down")
        .arg("-v")
        .env("AMBER_KVM_GID", kvm_gid.to_string())
        .output()
        .expect("failed to run docker compose down");
    if !output.status.success() {
        panic!(
            "docker compose down failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

#[test]
#[ignore = "requires /dev/kvm and docker"]
fn kvm_smoke_framework_kvm_example() {
    let kvm_gid = match kvm_gid() {
        Some(gid) => gid,
        None => {
            progress("/dev/kvm not available, skipping");
            return;
        }
    };

    progress("starting framework-kvm smoke test");
    let workspace_root = workspace_root();
    let outputs_root = cli_test_outputs_root(&workspace_root);
    fs::create_dir_all(&outputs_root).expect("failed to create outputs root");
    let temp = tempfile::Builder::new()
        .prefix("kvm-smoke-")
        .tempdir_in(&outputs_root)
        .expect("failed to create temp output directory");

    let compose_out = temp.path().join("compose-out");
    let runtime_bin_dir = ensure_runtime_binaries_built(&workspace_root);
    let amber = runtime_bin_dir.join("amber");
    let example_dir = workspace_root.join("examples").join("framework-kvm");

    ensure_internal_images(&workspace_root);
    build_checker_image(&workspace_root);
    compile_docker_compose_or_panic(&amber, &compose_out, &example_dir.join("scenario.json5"));

    let compose_file = compose_out.join("compose.yaml");
    docker_compose_up_or_panic(&compose_file, kvm_gid);
    docker_compose_down(&compose_file, kvm_gid);
    progress("finished framework-kvm smoke test");
}
