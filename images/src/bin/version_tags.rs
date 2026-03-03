use std::{
    env, fs,
    path::{Path, PathBuf},
    process,
};

use serde::{Deserialize, Serialize};
use tracing_subscriber::EnvFilter;

#[path = "../versioning.rs"]
mod versioning;

#[derive(Debug, Deserialize)]
struct Manifest {
    images: Vec<ImageSpec>,
}

#[derive(Debug, Deserialize)]
struct ImageSpec {
    name: String,
    #[serde(default)]
    version: Option<String>,
}

#[derive(Debug, Serialize)]
struct VersionTagManifest {
    images: Vec<ImageVersionTags>,
}

#[derive(Debug, Serialize)]
struct ImageVersionTags {
    name: String,
    version: String,
    runtime_tag: String,
    floating_tags: Vec<String>,
}

fn main() {
    init_tracing();

    let manifest_path = match env::args().nth(1) {
        Some(path) => PathBuf::from(path),
        None => default_manifest_path(),
    };

    let manifest = match read_manifest(&manifest_path) {
        Ok(manifest) => manifest,
        Err(err) => {
            tracing::error!("{err}");
            process::exit(1);
        }
    };

    let mut images = Vec::new();
    for image in manifest.images {
        let Some(version) = image.version else {
            continue;
        };
        let version = version.trim();
        if version.is_empty() {
            tracing::error!("image {} has an empty version", image.name);
            process::exit(1);
        }

        let parsed = match versioning::parse_manifest_version(version) {
            Ok(parsed) => parsed,
            Err(err) => {
                tracing::error!(
                    "image {} has invalid version {}: {err}",
                    image.name,
                    version
                );
                process::exit(1);
            }
        };

        images.push(ImageVersionTags {
            name: image.name,
            version: version.to_owned(),
            runtime_tag: versioning::runtime_tag(&parsed),
            floating_tags: versioning::floating_tags(&parsed),
        });
    }

    let out = VersionTagManifest { images };
    match serde_json::to_string(&out) {
        Ok(json) => println!("{json}"),
        Err(err) => {
            tracing::error!("failed to serialize version tag metadata: {err}");
            process::exit(1);
        }
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .init();
}

fn default_manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("images crate should live under workspace root")
        .join("docker")
        .join("images.json")
}

fn read_manifest(path: &Path) -> Result<Manifest, String> {
    let contents = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    serde_json::from_str(&contents)
        .map_err(|err| format!("failed to parse {}: {err}", path.display()))
}
