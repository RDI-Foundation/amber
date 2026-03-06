use std::{fmt::Write as _, fs, path::Path, process::Command};

#[path = "../src/example_catalog.rs"]
mod example_catalog;

#[test]
fn docs_readme_dumps_workspace_readme() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");
    let expected = fs::read_to_string(workspace_root.join("README.md"))
        .expect("failed to read workspace README");

    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("docs")
        .arg("readme")
        .output()
        .expect("failed to run `amber docs readme`");

    assert!(
        output.status.success(),
        "`amber docs readme` failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), expected);
    assert!(
        output.stderr.is_empty(),
        "expected no stderr from `amber docs readme`, got:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn docs_examples_lists_available_examples() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");
    let examples = example_catalog::collect_examples(&workspace_root.join("examples"))
        .expect("failed to collect examples");

    let name_width = examples
        .iter()
        .map(|example| example.name.len())
        .max()
        .unwrap_or(0);
    let mut expected = String::from("Examples\n\n");
    for example in &examples {
        let _ = writeln!(
            &mut expected,
            "{:<name_width$}  {}",
            example.name,
            example.summary,
            name_width = name_width
        );
    }
    expected.push_str("\nRun `amber docs examples <example>` to dump that example's files.\n");

    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("docs")
        .arg("examples")
        .output()
        .expect("failed to run `amber docs examples`");

    assert!(
        output.status.success(),
        "`amber docs examples` failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), expected);
    assert!(
        output.stderr.is_empty(),
        "expected no stderr from `amber docs examples`, got:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn docs_examples_dumps_example_files_with_paths() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");
    let example = example_catalog::collect_examples(&workspace_root.join("examples"))
        .expect("failed to collect examples")
        .into_iter()
        .find(|example| example.name == "reexport")
        .expect("expected reexport example");

    let mut expected = String::new();
    for (index, file) in example.files.iter().enumerate() {
        if index > 0 {
            expected.push('\n');
        }

        let relative_path = file
            .strip_prefix(workspace_root)
            .expect("example file should be under the workspace root");
        let _ = writeln!(&mut expected, "## `{}`\n", relative_path.display());
        let _ = writeln!(&mut expected, "```{}", fence_language(relative_path));

        let contents = fs::read_to_string(file)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", file.display()));
        expected.push_str(&contents);
        if !contents.ends_with('\n') {
            expected.push('\n');
        }
        expected.push_str("```\n");
    }

    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("docs")
        .arg("examples")
        .arg("reexport")
        .output()
        .expect("failed to run `amber docs examples reexport`");

    assert!(
        output.status.success(),
        "`amber docs examples reexport` failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), expected);
    assert!(
        output.stderr.is_empty(),
        "expected no stderr from `amber docs examples reexport`, got:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn docs_examples_reports_unknown_example() {
    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("docs")
        .arg("examples")
        .arg("does-not-exist")
        .output()
        .expect("failed to run `amber docs examples does-not-exist`");

    assert!(
        !output.status.success(),
        "`amber docs examples does-not-exist` unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "expected no stdout from unknown example error, got:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown example `does-not-exist`"),
        "expected helpful unknown example error, got:\n{stderr}"
    );
    assert!(
        stderr.contains("reexport"),
        "expected available examples in stderr, got:\n{stderr}"
    );
}

fn fence_language(path: &Path) -> &'static str {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("json") => "json",
        Some("json5") => "json5",
        Some("md") => "markdown",
        _ => "text",
    }
}
