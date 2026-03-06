#[path = "src/example_catalog.rs"]
mod example_catalog;

use std::{env, fs, path::Path};

fn main() {
    let manifest_dir_buf = std::path::PathBuf::from(
        env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR should be set"),
    );
    let manifest_dir = manifest_dir_buf.as_path();
    let workspace_root = manifest_dir
        .parent()
        .expect("cli crate should live under the workspace root");
    let examples_dir = workspace_root.join("examples");
    let examples = example_catalog::collect_examples(&examples_dir)
        .expect("failed to collect embedded example documentation");

    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("README.md").display()
    );
    println!("cargo:rerun-if-changed={}", examples_dir.display());
    for example in &examples {
        println!("cargo:rerun-if-changed={}", example.dir.display());
        println!("cargo:rerun-if-changed={}", example.root_manifest.display());
        let readme = example.dir.join("README.md");
        if readme.is_file() {
            println!("cargo:rerun-if-changed={}", readme.display());
        }
        for file in &example.files {
            println!("cargo:rerun-if-changed={}", file.display());
        }
    }

    let generated = render_example_docs(workspace_root, &examples);
    let out_dir_buf = std::path::PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR should be set"));
    fs::write(out_dir_buf.join("docs_examples.rs"), generated)
        .expect("failed to write generated example docs source");
}

fn render_example_docs(workspace_root: &Path, examples: &[example_catalog::Example]) -> String {
    let mut generated = String::from("static EXAMPLE_DOCS: &[ExampleDoc] = &[\n");

    for example in examples {
        generated.push_str("    ExampleDoc {\n");
        generated.push_str(&format!("        name: {:?},\n", example.name));
        generated.push_str(&format!("        summary: {:?},\n", example.summary));
        generated.push_str("        files: &[\n");
        for file in &example.files {
            let relative_path = file
                .strip_prefix(workspace_root)
                .expect("example file should live under the workspace root");
            generated.push_str("            ExampleFile {\n");
            generated.push_str(&format!(
                "                path: {:?},\n",
                relative_path.to_string_lossy()
            ));
            generated.push_str(&format!(
                "                contents: include_str!({:?}),\n",
                file.to_string_lossy()
            ));
            generated.push_str("            },\n");
        }
        generated.push_str("        ],\n");
        generated.push_str("    },\n");
    }

    generated.push_str("];\n");
    generated
}
