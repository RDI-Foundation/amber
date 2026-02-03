use std::{
    collections::HashSet,
    env,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Manifest {
    registry: String,
    images: Vec<ImageSpec>,
}

#[derive(Debug, Deserialize)]
struct ImageSpec {
    name: String,
    #[serde(default)]
    code_tag: Option<String>,
}

fn main() {
    let manifest_path = manifest_path();
    println!("cargo:rerun-if-changed={}", manifest_path.display());

    let manifest = read_manifest(&manifest_path);
    let registry = manifest.registry.trim_end_matches('/');
    if registry.is_empty() {
        panic!("docker/images.json registry must not be empty");
    }

    let mut const_names = HashSet::new();
    let mut code_images = Vec::new();

    for image in manifest.images {
        let Some(tag) = image.code_tag else {
            continue;
        };
        if tag.trim().is_empty() {
            panic!("image {} has an empty code_tag", image.name);
        }
        let const_name = const_name(&image.name);
        if const_name.is_empty() {
            panic!("image {} produced an empty constant name", image.name);
        }
        if !const_names.insert(const_name.clone()) {
            panic!(
                "duplicate constant name {const_name} for image {}",
                image.name
            );
        }
        let reference = format!("{registry}/{name}:{tag}", name = image.name);
        code_images.push(CodeImage {
            const_name,
            name: image.name,
            tag,
            reference,
        });
    }

    let mut out = String::new();
    writeln!(&mut out, "pub const REGISTRY: &str = {:?};", registry).unwrap();
    writeln!(&mut out).unwrap();

    for image in &code_images {
        writeln!(
            &mut out,
            "pub const {const_name}: ImageRef = ImageRef {{ name: {name:?}, tag: {tag:?}, \
             registry: REGISTRY, reference: {reference:?} }};",
            const_name = image.const_name,
            name = image.name,
            tag = image.tag,
            reference = image.reference,
        )
        .unwrap();
    }

    write!(&mut out, "\npub const CODE_IMAGES: &[ImageRef] = &[").unwrap();
    for (idx, image) in code_images.iter().enumerate() {
        if idx > 0 {
            out.push_str(", ");
        }
        out.push_str(&image.const_name);
    }
    out.push_str("];\n");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let out_path = out_dir.join("images.rs");
    fs::write(&out_path, out).expect("failed to write generated image refs");
}

fn manifest_path() -> PathBuf {
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    manifest_dir
        .parent()
        .expect("images crate should live under workspace root")
        .join("docker")
        .join("images.json")
}

fn read_manifest(path: &Path) -> Manifest {
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_str(&contents)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
}

fn const_name(name: &str) -> String {
    let mut out = String::new();
    let mut pending_underscore = false;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            if pending_underscore && !out.is_empty() {
                out.push('_');
            }
            pending_underscore = false;
            out.push(ch.to_ascii_uppercase());
        } else {
            pending_underscore = true;
        }
    }
    out
}

struct CodeImage {
    const_name: String,
    name: String,
    tag: String,
    reference: String,
}
