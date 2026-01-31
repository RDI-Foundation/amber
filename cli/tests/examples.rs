use std::{
    collections::HashSet,
    ffi::OsStr,
    path::{Path, PathBuf},
    process::Command,
};

use amber_manifest::{ComponentDecl, Manifest, ManifestUrl};

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
    let manifests = collect_example_manifests(dir);
    let manifest_set: HashSet<PathBuf> =
        manifests.iter().map(|path| canonicalize_or(path)).collect();

    let mut referenced = HashSet::new();

    for path in &manifests {
        let contents = std::fs::read_to_string(path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        let manifest: Manifest = contents
            .parse()
            .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));
        let base_dir = path.parent().unwrap_or(dir);

        for component in manifest.components().values() {
            let Some(manifest_ref) = (match component {
                ComponentDecl::Reference(reference) => Some(reference),
                ComponentDecl::Object(obj) => Some(&obj.manifest),
                _ => None,
            }) else {
                continue;
            };

            let Some(resolved) = resolve_manifest_ref(base_dir, manifest_ref) else {
                continue;
            };
            let resolved = canonicalize_or(&resolved);
            if manifest_set.contains(&resolved) {
                referenced.insert(resolved);
            }
        }
    }

    let mut roots: Vec<PathBuf> = manifests
        .into_iter()
        .filter(|path| !referenced.contains(&canonicalize_or(path)))
        .collect();
    roots.sort();
    roots
}

fn resolve_manifest_ref(
    base_dir: &Path,
    reference: &amber_manifest::ManifestRef,
) -> Option<PathBuf> {
    match &reference.url {
        ManifestUrl::Absolute(url) => {
            if url.scheme() == "file" {
                url.to_file_path().ok()
            } else {
                None
            }
        }
        ManifestUrl::Relative(rel) => {
            let rel_path = Path::new(rel.as_ref());
            if rel_path.is_absolute() {
                Some(rel_path.to_path_buf())
            } else {
                Some(base_dir.join(rel_path))
            }
        }
        _ => None,
    }
}

fn canonicalize_or(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

#[test]
fn examples_check_deny_warnings() {
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
