use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[path = "../src/example_catalog.rs"]
mod example_catalog;

#[test]
fn examples_check_deny_warnings() {
    let examples_dir = examples_dir();
    let mut manifests: Vec<PathBuf> = collect_examples()
        .into_iter()
        .map(|example| example.root_manifest)
        .collect();
    manifests.extend(collect_scenario_variants(&examples_dir));
    manifests.sort();
    manifests.dedup();
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

#[test]
fn examples_compile_from_ir_matches_manifest_outputs() {
    let amber = env!("CARGO_BIN_EXE_amber");
    let outputs_root = workspace_root().join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs root");

    for example in collect_examples() {
        if matches!(example_backend(&example), ExampleBackend::CheckOnly) {
            continue;
        }

        let safe_name = example.name.replace('/', "-");
        let temp = tempfile::Builder::new()
            .prefix(&format!("example-ir-{safe_name}-"))
            .tempdir_in(&outputs_root)
            .expect("failed to create temp output directory");
        let manifest_outputs = temp.path().join("manifest");
        let ir_outputs = temp.path().join("ir");

        compile_example_outputs(amber, &example, &example.root_manifest, &manifest_outputs);
        compile_example_outputs(
            amber,
            &example,
            &manifest_outputs.join("scenario.json"),
            &ir_outputs,
        );

        assert_same_file(
            &manifest_outputs.join("scenario.json"),
            &ir_outputs.join("scenario.json"),
        );
        assert_same_file(
            &manifest_outputs.join("scenario.dot"),
            &ir_outputs.join("scenario.dot"),
        );
        assert_same_file(
            &manifest_outputs.join("metadata.json"),
            &ir_outputs.join("metadata.json"),
        );

        match example_backend(&example) {
            ExampleBackend::DockerCompose => assert_same_dir(
                &manifest_outputs.join("docker-compose"),
                &ir_outputs.join("docker-compose"),
            ),
            ExampleBackend::Direct => {
                assert_same_dir(&manifest_outputs.join("direct"), &ir_outputs.join("direct"));
            }
            ExampleBackend::Vm => {
                assert_same_dir(&manifest_outputs.join("vm"), &ir_outputs.join("vm"));
            }
            ExampleBackend::CheckOnly => unreachable!("check-only examples are skipped above"),
        }
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root")
        .to_path_buf()
}

fn examples_dir() -> PathBuf {
    workspace_root().join("examples")
}

fn collect_examples() -> Vec<example_catalog::Example> {
    example_catalog::collect_examples(&examples_dir()).expect("failed to collect examples")
}

#[derive(Clone, Copy)]
enum ExampleBackend {
    DockerCompose,
    Direct,
    Vm,
    CheckOnly,
}

fn example_backend(example: &example_catalog::Example) -> ExampleBackend {
    if example.name == "direct-security" {
        ExampleBackend::Direct
    } else if example.name == "vm-network-storage" {
        ExampleBackend::Vm
    } else if example.name == "interpolation" {
        ExampleBackend::CheckOnly
    } else {
        ExampleBackend::DockerCompose
    }
}

fn compile_example_outputs(
    amber: &str,
    example: &example_catalog::Example,
    input: &Path,
    output_root: &Path,
) {
    let scenario_output = output_root.join("scenario.json");
    let dot_output = output_root.join("scenario.dot");
    let metadata_output = output_root.join("metadata.json");

    let mut command = Command::new(amber);
    command
        .arg("compile")
        .arg("--output")
        .arg(&scenario_output)
        .arg("--dot")
        .arg(&dot_output)
        .arg("--metadata")
        .arg(&metadata_output);

    match example_backend(example) {
        ExampleBackend::DockerCompose => {
            command
                .arg("--docker-compose")
                .arg(output_root.join("docker-compose"));
        }
        ExampleBackend::Direct => {
            command.arg("--direct").arg(output_root.join("direct"));
        }
        ExampleBackend::Vm => {
            command.arg("--vm").arg(output_root.join("vm"));
        }
        ExampleBackend::CheckOnly => {
            panic!(
                "check-only examples should not be compiled: {}",
                example.name
            );
        }
    }

    let output = command
        .arg(input)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile for {}: {err}", example.name));
    if output.status.success() {
        return;
    }

    panic!(
        "amber compile failed for example {}\ninput: {}\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        example.name,
        input.display(),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn assert_same_file(left: &Path, right: &Path) {
    let left_bytes =
        fs::read(left).unwrap_or_else(|err| panic!("failed to read {}: {err}", left.display()));
    let right_bytes =
        fs::read(right).unwrap_or_else(|err| panic!("failed to read {}: {err}", right.display()));
    assert_eq!(
        left_bytes,
        right_bytes,
        "file contents differ:\nleft: {}\nright: {}",
        left.display(),
        right.display(),
    );
}

fn assert_same_dir(left: &Path, right: &Path) {
    let left_files = relative_files(left);
    let right_files = relative_files(right);
    assert_eq!(
        left_files,
        right_files,
        "directory trees differ:\nleft: {}\nright: {}",
        left.display(),
        right.display(),
    );

    for rel_path in left_files {
        assert_same_file(&left.join(&rel_path), &right.join(&rel_path));
    }
}

fn relative_files(root: &Path) -> Vec<PathBuf> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
        let mut entries: Vec<PathBuf> = fs::read_dir(dir)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", dir.display()))
            .map(|entry| {
                entry
                    .unwrap_or_else(|err| {
                        panic!("failed to read entry in {}: {err}", dir.display())
                    })
                    .path()
            })
            .collect();
        entries.sort();

        for entry in entries {
            if entry.is_dir() {
                walk(root, &entry, out);
            } else if entry.is_file() {
                out.push(
                    entry
                        .strip_prefix(root)
                        .expect("entry should live under root")
                        .to_path_buf(),
                );
            }
        }
    }

    let mut files = Vec::new();
    walk(root, root, &mut files);
    files
}

fn collect_scenario_variants(dir: &Path) -> Vec<PathBuf> {
    let mut stack = vec![dir.to_path_buf()];
    let mut manifests = Vec::new();

    while let Some(path) = stack.pop() {
        let entries = fs::read_dir(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        for entry in entries {
            let entry = entry
                .unwrap_or_else(|err| panic!("failed to read {} entry: {err}", path.display()));
            let entry_path = entry.path();
            if entry_path.is_dir() {
                stack.push(entry_path);
                continue;
            }
            let Some(name) = entry_path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some(ext) = entry_path.extension().and_then(|ext| ext.to_str()) else {
                continue;
            };
            if matches!(ext, "json" | "json5") && name.starts_with("scenario-") {
                manifests.push(entry_path);
            }
        }
    }

    manifests.sort();
    manifests
}
