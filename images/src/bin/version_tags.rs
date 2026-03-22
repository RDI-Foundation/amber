use std::{
    env, fs,
    path::{Path, PathBuf},
    process,
    process::Command,
};

use amber_images::versioning;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing_subscriber::EnvFilter;

const OCI_REVISION_ANNOTATION: &str = "org.opencontainers.image.revision";

#[derive(Debug, PartialEq, Eq)]
struct CliArgs {
    manifest_path: PathBuf,
    resolver: Option<ResolverConfig>,
}

#[derive(Debug, PartialEq, Eq)]
struct ResolverConfig {
    registry: String,
    sha: String,
}

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

    let args = match parse_args() {
        Ok(args) => args,
        Err(err) => {
            tracing::error!("{err}");
            process::exit(1);
        }
    };

    let manifest = match read_manifest(&args.manifest_path) {
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

        let spec = match versioning::parse_manifest_version_spec(version) {
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

        let resolved = match resolve_version(&image.name, version, &spec, args.resolver.as_ref()) {
            Ok(resolved) => resolved,
            Err(err) => {
                tracing::error!("{err}");
                process::exit(1);
            }
        };

        images.push(ImageVersionTags {
            name: image.name,
            version: resolved.version,
            runtime_tag: versioning::runtime_tag(&resolved.parsed),
            floating_tags: versioning::floating_tags(&resolved.parsed),
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

fn parse_args() -> Result<CliArgs, String> {
    parse_args_from(env::args().skip(1))
}

fn parse_args_from<I>(args: I) -> Result<CliArgs, String>
where
    I: IntoIterator<Item = String>,
{
    let mut manifest_path = None;
    let mut resolve = false;
    let mut registry = None;
    let mut sha = None;

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        if arg == "--resolve" {
            resolve = true;
            continue;
        }

        if arg == "--registry" {
            let value = iter
                .next()
                .ok_or_else(|| "--registry requires a value".to_string())?;
            registry = Some(value);
            continue;
        }

        if let Some(value) = arg.strip_prefix("--registry=") {
            if value.is_empty() {
                return Err("--registry requires a non-empty value".to_string());
            }
            registry = Some(value.to_string());
            continue;
        }

        if arg == "--sha" {
            let value = iter
                .next()
                .ok_or_else(|| "--sha requires a value".to_string())?;
            sha = Some(value);
            continue;
        }

        if let Some(value) = arg.strip_prefix("--sha=") {
            if value.is_empty() {
                return Err("--sha requires a non-empty value".to_string());
            }
            sha = Some(value.to_string());
            continue;
        }

        if arg.starts_with('-') {
            return Err(format!("unknown argument: {arg}"));
        }

        if manifest_path.is_some() {
            return Err("expected at most one manifest path".to_string());
        }
        manifest_path = Some(PathBuf::from(arg));
    }

    let manifest_path = manifest_path.unwrap_or_else(default_manifest_path);
    let resolver = if resolve {
        let registry = registry
            .ok_or_else(|| "--resolve requires --registry".to_string())?
            .trim()
            .trim_end_matches('/')
            .to_string();
        if registry.is_empty() {
            return Err("--registry must not be empty".to_string());
        }

        let sha = sha
            .ok_or_else(|| "--resolve requires --sha".to_string())?
            .trim()
            .to_string();
        if sha.is_empty() {
            return Err("--sha must not be empty".to_string());
        }

        Some(ResolverConfig { registry, sha })
    } else {
        if registry.is_some() || sha.is_some() {
            return Err("--registry/--sha require --resolve".to_string());
        }
        None
    };

    Ok(CliArgs {
        manifest_path,
        resolver,
    })
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

struct ResolvedVersion {
    version: String,
    parsed: Version,
}

#[derive(Debug, PartialEq, Eq)]
struct ManifestMetadata {
    signature: String,
    revision: Option<String>,
}

fn resolve_version(
    image_name: &str,
    raw_version: &str,
    spec: &versioning::ManifestVersionSpec,
    resolver: Option<&ResolverConfig>,
) -> Result<ResolvedVersion, String> {
    match spec {
        versioning::ManifestVersionSpec::Concrete(version) => Ok(ResolvedVersion {
            version: raw_version.to_string(),
            parsed: version.clone(),
        }),
        versioning::ManifestVersionSpec::Wildcard(_) => {
            let resolved_version = match resolver {
                Some(resolver) => resolve_wildcard_version(image_name, raw_version, resolver)?,
                None => raw_version.to_string(),
            };
            let parsed = if resolver.is_some() {
                versioning::parse_manifest_version(&resolved_version).map_err(|err| {
                    format!(
                        "failed to parse resolved version {} for image {}: {}",
                        resolved_version, image_name, err
                    )
                })?
            } else {
                spec.seed_version().clone()
            };

            Ok(ResolvedVersion {
                version: resolved_version,
                parsed,
            })
        }
    }
}

fn resolve_wildcard_version(
    image_name: &str,
    raw_version: &str,
    resolver: &ResolverConfig,
) -> Result<String, String> {
    let wildcard_prefix = raw_version
        .strip_suffix('x')
        .ok_or_else(|| format!("wildcard version for {image_name} does not end with x"))?;
    let sha_ref = image_ref(&resolver.registry, image_name, &resolver.sha);
    let sha_signature = manifest_metadata(&sha_ref)?
        .ok_or_else(|| format!("sha tag does not exist for {image_name}: {sha_ref}"))?
        .signature;

    let mut sequence = 0_u64;
    loop {
        let candidate = format!("{wildcard_prefix}{sequence}");
        let candidate_ref = image_ref(&resolver.registry, image_name, &candidate);
        match manifest_metadata(&candidate_ref)? {
            Some(existing) if existing.revision.as_deref() == Some(resolver.sha.as_str()) => {
                return Ok(candidate);
            }
            Some(existing) if existing.signature == sha_signature => {
                return Ok(candidate);
            }
            Some(_) => {}
            None => return Ok(candidate),
        }

        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| format!("no wildcard versions remain for image {image_name}"))?;
    }
}

fn image_ref(registry: &str, image: &str, tag: &str) -> String {
    format!("{registry}/{image}:{tag}")
}

fn manifest_metadata(reference: &str) -> Result<Option<ManifestMetadata>, String> {
    let raw = match inspect_raw_manifest(reference)? {
        Some(raw) => raw,
        None => return Ok(None),
    };
    manifest_metadata_from_raw(reference, &raw).map(Some)
}

fn manifest_metadata_from_raw(reference: &str, raw: &str) -> Result<ManifestMetadata, String> {
    let mut manifest: Value = serde_json::from_str(raw)
        .map_err(|err| format!("failed to parse manifest for {reference}: {err}"))?;
    let revision = manifest_revision(&manifest).map(ToOwned::to_owned);
    normalize_manifest(&mut manifest);
    let signature = serde_json::to_string(&manifest)
        .map_err(|err| format!("failed to serialize normalized manifest for {reference}: {err}"))?;
    Ok(ManifestMetadata {
        signature,
        revision,
    })
}

fn inspect_raw_manifest(reference: &str) -> Result<Option<String>, String> {
    let output = Command::new("docker")
        .args(["buildx", "imagetools", "inspect", "--raw", reference])
        .output()
        .map_err(|err| format!("failed to run docker buildx imagetools inspect: {err}"))?;

    if output.status.success() {
        return String::from_utf8(output.stdout)
            .map(Some)
            .map_err(|err| format!("docker inspect output for {reference} was not UTF-8: {err}"));
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = if stderr.trim().is_empty() {
        stdout.trim().to_string()
    } else {
        stderr.trim().to_string()
    };

    if looks_like_missing_manifest(&detail) {
        return Ok(None);
    }

    Err(format!(
        "failed to inspect {reference} (exit {}): {detail}",
        output.status
    ))
}

fn looks_like_missing_manifest(detail: &str) -> bool {
    let lower = detail.to_ascii_lowercase();
    lower.contains("no such manifest")
        || lower.contains("manifest unknown")
        || lower.contains("not found")
}

fn manifest_revision(manifest: &Value) -> Option<&str> {
    manifest
        .get("annotations")
        .and_then(Value::as_object)
        .and_then(|annotations| annotations.get(OCI_REVISION_ANNOTATION))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn normalize_manifest(manifest: &mut Value) {
    let Some(entries) = manifest.get_mut("manifests").and_then(Value::as_array_mut) else {
        return;
    };

    entries.sort_by_key(manifest_sort_key);
}

fn manifest_sort_key(manifest: &Value) -> (String, String, String, String) {
    let platform = manifest
        .get("platform")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let os = platform
        .get("os")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let arch = platform
        .get("architecture")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let variant = platform
        .get("variant")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let digest = manifest
        .get("digest")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    (os, arch, variant, digest)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::json;

    use super::{
        CliArgs, ResolverConfig, manifest_metadata_from_raw, manifest_revision, parse_args_from,
    };

    #[test]
    fn parse_args_without_resolver() {
        let args = parse_args_from(["docker/images.json".to_string()])
            .expect("args without resolver should parse");
        assert_eq!(
            args,
            CliArgs {
                manifest_path: PathBuf::from("docker/images.json"),
                resolver: None
            }
        );
    }

    #[test]
    fn parse_args_with_resolver() {
        let args = parse_args_from([
            "--resolve".to_string(),
            "--registry".to_string(),
            "ghcr.io/rdi-foundation".to_string(),
            "--sha".to_string(),
            "abc123".to_string(),
            "docker/images.json".to_string(),
        ])
        .expect("resolver args should parse");
        assert_eq!(
            args,
            CliArgs {
                manifest_path: PathBuf::from("docker/images.json"),
                resolver: Some(ResolverConfig {
                    registry: "ghcr.io/rdi-foundation".to_string(),
                    sha: "abc123".to_string(),
                }),
            }
        );
    }

    #[test]
    fn parse_args_rejects_registry_without_resolve() {
        let err = parse_args_from(["--registry=ghcr.io/rdi-foundation".to_string()])
            .expect_err("registry without resolve should fail");
        assert_eq!(err, "--registry/--sha require --resolve");
    }

    #[test]
    fn manifest_revision_reads_oci_revision_annotation() {
        let manifest = json!({
            "annotations": {
                "org.opencontainers.image.revision": "abc123"
            }
        });
        assert_eq!(manifest_revision(&manifest), Some("abc123"));
    }

    #[test]
    fn manifest_metadata_preserves_revision_when_normalizing_signature() {
        let raw = json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "annotations": {
                "org.opencontainers.image.revision": "abc123"
            },
            "manifests": [
                {
                    "digest": "sha256:b",
                    "platform": {
                        "architecture": "arm64",
                        "os": "linux"
                    }
                },
                {
                    "digest": "sha256:a",
                    "platform": {
                        "architecture": "amd64",
                        "os": "linux"
                    }
                }
            ]
        });

        let metadata = manifest_metadata_from_raw("test-ref", &raw.to_string())
            .expect("manifest metadata should parse");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&metadata.signature)
                .expect("normalized signature should be valid json"),
            json!({
                "annotations": {
                    "org.opencontainers.image.revision": "abc123"
                },
                "manifests": [
                    {
                        "digest": "sha256:a",
                        "platform": {
                            "architecture": "amd64",
                            "os": "linux"
                        }
                    },
                    {
                        "digest": "sha256:b",
                        "platform": {
                            "architecture": "arm64",
                            "os": "linux"
                        }
                    }
                ],
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "schemaVersion": 2
            })
        );
        assert_eq!(metadata.revision, Some("abc123".to_string()));
    }
}
