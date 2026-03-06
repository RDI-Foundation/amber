use std::{
    path::{Path, PathBuf},
    process::Command,
};

#[path = "../src/example_catalog.rs"]
mod example_catalog;

#[test]
fn examples_check_deny_warnings() {
    let examples_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("examples");
    let manifests: Vec<PathBuf> = example_catalog::collect_examples(&examples_dir)
        .expect("failed to collect examples")
        .into_iter()
        .map(|example| example.root_manifest)
        .collect();
    assert!(
        !manifests.is_empty(),
        "no root example manifests found in {}",
        examples_dir.display()
    );

    let amber = env!("CARGO_BIN_EXE_amber");
    for manifest in manifests {
        let output = Command::new(amber)
            .arg("check")
            .arg("-D")
            .arg("warnings")
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
