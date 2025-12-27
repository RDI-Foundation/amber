use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    process::Command,
};

use amber_manifest::Manifest;

fn collect_example_manifests(dir: &Path) -> Vec<PathBuf> {
    let mut stack = vec![dir.to_path_buf()];
    let mut manifests = Vec::new();

    while let Some(path) = stack.pop() {
        for entry in std::fs::read_dir(&path).expect("failed to read examples directory") {
            let entry = entry.expect("failed to read examples entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }

            let ext = path.extension().and_then(OsStr::to_str);
            if matches!(ext, Some("json5") | Some("json")) {
                manifests.push(path);
            }
        }
    }

    manifests.sort();
    manifests
}

fn collect_root_manifests(dir: &Path) -> Vec<PathBuf> {
    let mut manifests = Vec::new();
    for path in collect_example_manifests(dir) {
        let contents = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        let manifest: Manifest = contents
            .parse()
            .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));
        if manifest.slots().is_empty() {
            manifests.push(path);
        }
    }
    manifests.sort();
    manifests
}

#[test]
fn examples_check() {
    let examples_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("examples");
    let manifests = collect_root_manifests(&examples_dir);
    assert!(
        !manifests.is_empty(),
        "no root example manifests found in {}",
        examples_dir.display()
    );

    let amber = env!("CARGO_BIN_EXE_amber");
    for manifest in manifests {
        let output = Command::new(amber)
            .arg("check")
            .arg(&manifest)
            .output()
            .unwrap_or_else(|err| panic!("failed to run amber on {}: {err}", manifest.display()));

        if !output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            panic!(
                "amber check failed for {}\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
                manifest.display(),
                output.status,
                stdout,
                stderr
            );
        }
    }
}
