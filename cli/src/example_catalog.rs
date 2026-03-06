use std::{
    collections::HashSet,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

use amber_manifest::{ComponentDecl, Manifest, ManifestUrl};

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct Example {
    pub(crate) name: String,
    pub(crate) summary: String,
    pub(crate) dir: PathBuf,
    pub(crate) root_manifest: PathBuf,
    pub(crate) files: Vec<PathBuf>,
}

pub(crate) fn collect_examples(examples_dir: &Path) -> Result<Vec<Example>, String> {
    let root_manifests = collect_root_manifests(examples_dir)?;
    let workspace_root = examples_dir.parent().ok_or_else(|| {
        format!(
            "examples directory `{}` has no parent",
            examples_dir.display()
        )
    })?;

    let mut examples = Vec::with_capacity(root_manifests.len());
    let mut names = HashSet::new();

    for root_manifest in root_manifests {
        let dir = root_manifest.parent().ok_or_else(|| {
            format!(
                "root manifest `{}` has no parent directory",
                root_manifest.display()
            )
        })?;
        let name = dir
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| format!("invalid example directory name `{}`", dir.display()))?
            .to_owned();

        if !names.insert(name.clone()) {
            return Err(format!(
                "multiple root manifests map to example `{name}` in `{}`",
                dir.display()
            ));
        }

        let files = collect_example_files(dir)?;
        let summary = read_example_summary(dir)?.unwrap_or_else(|| {
            let relative_root = root_manifest
                .strip_prefix(workspace_root)
                .unwrap_or(&root_manifest);
            format!("Example rooted at `{}`.", relative_root.display())
        });

        examples.push(Example {
            name,
            summary,
            dir: dir.to_path_buf(),
            root_manifest,
            files,
        });
    }

    examples.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(examples)
}

fn collect_example_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut stack = vec![dir.to_path_buf()];
    let mut files = Vec::new();

    while let Some(path) = stack.pop() {
        let entries = fs::read_dir(&path).map_err(|err| {
            format!(
                "failed to read example directory `{}`: {err}",
                path.display()
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|err| {
                format!(
                    "failed to read directory entry in `{}`: {err}",
                    path.display()
                )
            })?;
            let entry_path = entry.path();
            if entry_path.is_dir() {
                stack.push(entry_path);
            } else if entry_path.is_file()
                && entry_path.file_name().and_then(OsStr::to_str) != Some("README.md")
            {
                files.push(entry_path);
            }
        }
    }

    files.sort_by(|left, right| {
        let left_name = left.file_name().and_then(OsStr::to_str);
        let right_name = right.file_name().and_then(OsStr::to_str);
        match (
            left_name == Some("README.md"),
            right_name == Some("README.md"),
        ) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => left.cmp(right),
        }
    });
    Ok(files)
}

fn collect_example_manifests(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut stack = vec![dir.to_path_buf()];
    let mut manifests = Vec::new();

    while let Some(path) = stack.pop() {
        let entries = fs::read_dir(&path).map_err(|err| {
            format!(
                "failed to read examples directory `{}`: {err}",
                path.display()
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|err| {
                format!(
                    "failed to read examples entry in `{}`: {err}",
                    path.display()
                )
            })?;
            let entry_path = entry.path();
            if entry_path.is_dir() {
                stack.push(entry_path);
                continue;
            }

            let ext = entry_path.extension().and_then(OsStr::to_str);
            if matches!(ext, Some("json5") | Some("json")) {
                manifests.push(entry_path);
            }
        }
    }

    manifests.sort();
    Ok(manifests)
}

fn collect_root_manifests(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let manifests = collect_example_manifests(dir)?;
    let manifest_set: HashSet<PathBuf> =
        manifests.iter().map(|path| canonicalize_or(path)).collect();

    let mut referenced = HashSet::new();

    for path in &manifests {
        let contents = fs::read_to_string(path)
            .map_err(|err| format!("failed to read `{}`: {err}", path.display()))?;
        let manifest: Manifest = contents
            .parse()
            .map_err(|err| format!("failed to parse `{}`: {err}", path.display()))?;
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
    Ok(roots)
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

fn read_example_summary(dir: &Path) -> Result<Option<String>, String> {
    let readme = dir.join("README.md");
    if !readme.is_file() {
        return Ok(None);
    }

    let contents = fs::read_to_string(&readme)
        .map_err(|err| format!("failed to read `{}`: {err}", readme.display()))?;
    if let Some(summary) = read_hidden_summary(&readme, &contents)? {
        return Ok(Some(summary));
    }

    Ok(first_readme_paragraph(&contents))
}

fn read_hidden_summary(readme: &Path, contents: &str) -> Result<Option<String>, String> {
    let trimmed = contents.trim_start();
    if !trimmed.starts_with("<!--") {
        return Ok(None);
    }

    let Some(comment_end) = trimmed.find("-->") else {
        return Err(format!(
            "README metadata comment in `{}` is not terminated",
            readme.display()
        ));
    };
    let comment = &trimmed["<!--".len()..comment_end];
    let mut lines = comment
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    let Some(header) = lines.next() else {
        return Ok(None);
    };
    if header != "amber-docs" {
        return Ok(None);
    }

    let mut summary = None;
    for line in lines {
        let Some((key, value)) = line.split_once(':') else {
            return Err(format!(
                "invalid README metadata line `{line}` in `{}`; expected `key: value`",
                readme.display()
            ));
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "summary" => {
                if value.is_empty() {
                    return Err(format!(
                        "README metadata `summary` in `{}` must not be empty",
                        readme.display()
                    ));
                }
                if summary.replace(value.to_owned()).is_some() {
                    return Err(format!(
                        "duplicate README metadata `summary` in `{}`",
                        readme.display()
                    ));
                }
            }
            other => {
                return Err(format!(
                    "unknown README metadata key `{other}` in `{}`",
                    readme.display()
                ));
            }
        }
    }

    match summary {
        Some(summary) => Ok(Some(summary)),
        None => Err(format!(
            "README metadata block in `{}` is missing `summary:`",
            readme.display()
        )),
    }
}

fn first_readme_paragraph(contents: &str) -> Option<String> {
    let mut after_title = false;
    let mut paragraph = Vec::new();

    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if !after_title {
            if line.starts_with("# ") {
                after_title = true;
            }
            continue;
        }

        if line.is_empty() {
            if paragraph.is_empty() {
                continue;
            }
            break;
        }

        if line.starts_with('#') && paragraph.is_empty() {
            continue;
        }

        if line.starts_with('#') {
            break;
        }

        paragraph.push(line);
    }

    if paragraph.is_empty() {
        None
    } else {
        Some(paragraph.join(" "))
    }
}
