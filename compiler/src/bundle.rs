#![allow(clippy::result_large_err)]

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    io::{self, Write as _},
    path::{Path, PathBuf},
    sync::Arc,
};

use amber_manifest::{ManifestDigest, ManifestRef, ParsedManifest};
use amber_resolver::{Backend, RemoteResolver, Resolution, Resolver};
use base64::Engine as _;
use miette::Diagnostic;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::{
    DigestStore, ResolverRegistry,
    frontend::{ResolvedNode, ResolvedTree},
};

pub const BUNDLE_SCHEMA: &str = "amber.bundle";
pub const BUNDLE_VERSION: u32 = 1;
pub const BUNDLE_INDEX_NAME: &str = "bundle.json";
const BUNDLE_MANIFEST_DIR: &str = "manifests";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleRequest {
    pub url: Url,
    pub digest: ManifestDigest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleIndex {
    pub schema: String,
    pub version: u32,
    pub root_url: Url,
    pub requests: Vec<BundleRequest>,
}

impl BundleIndex {
    pub fn new(root_url: Url, mut requests: Vec<BundleRequest>) -> Self {
        requests.sort_by(|a, b| a.url.as_str().cmp(b.url.as_str()));
        Self {
            schema: BUNDLE_SCHEMA.to_string(),
            version: BUNDLE_VERSION,
            root_url,
            requests,
        }
    }

    fn ensure_supported(&self) -> Result<(), Error> {
        if self.schema != BUNDLE_SCHEMA {
            return Err(Error::InvalidSchema {
                schema: self.schema.clone(),
                expected: BUNDLE_SCHEMA,
            });
        }
        if self.version != BUNDLE_VERSION {
            return Err(Error::InvalidVersion {
                version: self.version,
                expected: BUNDLE_VERSION,
            });
        }
        Ok(())
    }

    fn requests_by_url(&self) -> Result<HashMap<Url, ManifestDigest>, Error> {
        let mut map = HashMap::new();
        for request in &self.requests {
            match map.entry(request.url.clone()) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(request.digest);
                }
                std::collections::hash_map::Entry::Occupied(entry) => {
                    let existing = *entry.get();
                    if existing != request.digest {
                        return Err(Error::ConflictingDigests {
                            url: request.url.clone(),
                            first: existing,
                            second: request.digest,
                        });
                    }
                    return Err(Error::DuplicateRequest {
                        url: request.url.clone(),
                    });
                }
            }
        }
        Ok(map)
    }

    fn write_to(&self, path: &Path) -> Result<(), Error> {
        let mut bytes = serde_json::to_vec_pretty(self)?;
        bytes.push(b'\n');
        std::fs::write(path, bytes)?;
        Ok(())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let index: BundleIndex = serde_json::from_slice(bytes)?;
        index.ensure_supported()?;
        Ok(index)
    }

    fn maybe_from_bytes(bytes: &[u8]) -> Result<Option<Self>, Error> {
        let value: serde_json::Value = match serde_json::from_slice(bytes) {
            Ok(value) => value,
            Err(_) => return Ok(None),
        };

        let Some(obj) = value.as_object() else {
            return Ok(None);
        };
        let Some(schema) = obj.get("schema").and_then(|v| v.as_str()) else {
            return Ok(None);
        };
        let Some(version) = obj.get("version").and_then(|v| v.as_u64()) else {
            return Ok(None);
        };
        if schema != BUNDLE_SCHEMA || version != BUNDLE_VERSION as u64 {
            return Ok(None);
        }

        let index: BundleIndex = serde_json::from_value(value)?;
        index.ensure_supported()?;
        Ok(Some(index))
    }
}

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum Error {
    #[error("unsupported bundle schema `{schema}` (expected `{expected}`)")]
    #[diagnostic(code(bundle::schema_mismatch))]
    InvalidSchema {
        schema: String,
        expected: &'static str,
    },

    #[error("unsupported bundle version {version} (expected {expected})")]
    #[diagnostic(code(bundle::version_mismatch))]
    InvalidVersion { version: u32, expected: u32 },

    #[error("bundle root URL `{root_url}` is missing from the request table")]
    #[diagnostic(code(bundle::missing_root_url))]
    MissingRootUrl { root_url: Url },

    #[error("bundle URL `{url}` maps to multiple digests ({first} vs {second})")]
    #[diagnostic(code(bundle::conflicting_digests))]
    ConflictingDigests {
        url: Url,
        first: ManifestDigest,
        second: ManifestDigest,
    },

    #[error("bundle URL `{url}` appears more than once in requests")]
    #[diagnostic(code(bundle::duplicate_request))]
    DuplicateRequest { url: Url },

    #[error("missing manifest for digest `{digest}` in the store")]
    #[diagnostic(code(bundle::missing_manifest))]
    MissingManifest { digest: ManifestDigest },

    #[error("manifest digest mismatch in `{path}` (expected `{expected}`, got `{actual}`)")]
    #[diagnostic(code(bundle::mismatched_digest))]
    MismatchedDigest {
        path: PathBuf,
        expected: ManifestDigest,
        actual: ManifestDigest,
    },

    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    #[diagnostic(transparent)]
    Manifest(#[from] amber_manifest::ManifestDocError),

    #[error(transparent)]
    #[diagnostic(transparent)]
    Resolver(#[from] amber_resolver::Error),
}

pub struct BundleBuilder;

impl BundleBuilder {
    pub fn build(
        tree: &ResolvedTree,
        store: &DigestStore,
        bundle_root: impl AsRef<Path>,
    ) -> Result<BundleIndex, Error> {
        let bundle_root = bundle_root.as_ref();
        std::fs::create_dir_all(bundle_root)?;
        let manifest_root = bundle_root.join(BUNDLE_MANIFEST_DIR);
        std::fs::create_dir_all(&manifest_root)?;

        let mut requests_by_url = HashMap::new();
        let mut source_url_by_digest = HashMap::new();
        collect_bundle_requests(
            &tree.root,
            store,
            &mut requests_by_url,
            &mut source_url_by_digest,
        )?;

        let root_url = tree.root.resolved_url.clone();
        if !requests_by_url.contains_key(&root_url) {
            return Err(Error::MissingRootUrl { root_url });
        }

        let requests = requests_by_url
            .iter()
            .map(|(url, digest)| BundleRequest {
                url: url.clone(),
                digest: *digest,
            })
            .collect();

        write_bundle_manifests(bundle_root, store, &requests_by_url, &source_url_by_digest)?;

        let index = BundleIndex::new(root_url, requests);
        let index_path = bundle_root.join(BUNDLE_INDEX_NAME);
        index.write_to(&index_path)?;

        validate_bundle(&index, bundle_root)?;

        Ok(index)
    }
}

pub struct BundleLoader {
    bundle_root: PathBuf,
    index: BundleIndex,
}

impl BundleLoader {
    pub fn from_root(bundle_root: impl AsRef<Path>) -> Result<Self, Error> {
        let bundle_root = bundle_root.as_ref().to_path_buf();
        let index_path = bundle_root.join(BUNDLE_INDEX_NAME);
        let index = read_bundle_index(&index_path)?;
        Ok(Self { bundle_root, index })
    }

    pub fn from_index_path(index_path: impl AsRef<Path>) -> Result<Self, Error> {
        let index_path = index_path.as_ref().to_path_buf();
        let bundle_root = bundle_root_for_index(&index_path);
        let index = read_bundle_index(&index_path)?;
        Ok(Self { bundle_root, index })
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Option<Self>, Error> {
        let path = path.as_ref();
        let metadata = match std::fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        };

        if metadata.is_dir() {
            let index_path = path.join(BUNDLE_INDEX_NAME);
            let Some(index) = maybe_read_bundle_index(&index_path)? else {
                return Ok(None);
            };
            return Ok(Some(Self {
                bundle_root: path.to_path_buf(),
                index,
            }));
        }

        if metadata.is_file() {
            let Some(index) = maybe_read_bundle_index(path)? else {
                return Ok(None);
            };
            return Ok(Some(Self {
                bundle_root: bundle_root_for_index(path),
                index,
            }));
        }

        Ok(None)
    }

    pub fn bundle_root(&self) -> &Path {
        &self.bundle_root
    }

    pub fn index(&self) -> &BundleIndex {
        &self.index
    }

    pub async fn load(self) -> Result<BundleLoad, Error> {
        self.index.ensure_supported()?;
        let requests_by_url = self.index.requests_by_url()?;
        if !requests_by_url.contains_key(&self.index.root_url) {
            return Err(Error::MissingRootUrl {
                root_url: self.index.root_url.clone(),
            });
        }

        let schemes = collect_bundle_schemes(&requests_by_url);
        let backend = Arc::new(BundleResolver {
            bundle_root: self.bundle_root.clone(),
            requests_by_url: Arc::new(requests_by_url),
        });
        let bundle_remote = RemoteResolver::new(schemes, backend);

        let registry = load_bundle_registry(&bundle_remote, &self.index).await?;
        let resolver = Resolver::new().with_remote(bundle_remote);
        let root = ManifestRef::from_url(self.index.root_url.clone());

        Ok(BundleLoad {
            root,
            resolver,
            registry,
        })
    }
}

pub struct BundleLoad {
    pub root: ManifestRef,
    pub resolver: Resolver,
    pub registry: ResolverRegistry,
}

struct BundleResolver {
    bundle_root: PathBuf,
    requests_by_url: Arc<HashMap<Url, ManifestDigest>>,
}

impl Backend for BundleResolver {
    fn resolve_url<'a>(
        &'a self,
        url: &'a Url,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Resolution, amber_resolver::Error>> + Send + 'a,
        >,
    > {
        let url = url.clone();
        Box::pin(async move {
            let Some(digest) = self.requests_by_url.get(&url).copied() else {
                return Err(amber_resolver::Error::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("bundle entry not found for {url}"),
                )));
            };

            let path = bundle_manifest_path(&self.bundle_root, &digest);
            let source: Arc<str> = tokio::fs::read_to_string(&path).await?.into();
            let parsed = ParsedManifest::parse_named(url.as_str(), source)?;
            let manifest = parsed.manifest;
            if manifest.digest() != digest {
                return Err(amber_resolver::Error::MismatchedDigest(url));
            }

            Ok(Resolution {
                url,
                manifest,
                source: parsed.source,
                spans: parsed.spans,
            })
        })
    }
}

fn collect_bundle_requests(
    node: &ResolvedNode,
    store: &DigestStore,
    requests_by_url: &mut HashMap<Url, ManifestDigest>,
    source_url_by_digest: &mut HashMap<ManifestDigest, Url>,
) -> Result<(), Error> {
    let url = node.resolved_url.clone();
    let digest = node.digest;

    match requests_by_url.entry(url.clone()) {
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(digest);
        }
        std::collections::hash_map::Entry::Occupied(entry) => {
            let existing = *entry.get();
            if existing != digest {
                return Err(Error::ConflictingDigests {
                    url,
                    first: existing,
                    second: digest,
                });
            }
        }
    }

    if store.get_source(&url).is_some() {
        source_url_by_digest.entry(digest).or_insert(url);
    }

    for child in node.children.values() {
        collect_bundle_requests(child, store, requests_by_url, source_url_by_digest)?;
    }

    Ok(())
}

fn write_bundle_manifests(
    bundle_root: &Path,
    store: &DigestStore,
    requests_by_url: &HashMap<Url, ManifestDigest>,
    source_url_by_digest: &HashMap<ManifestDigest, Url>,
) -> Result<(), Error> {
    let mut written = HashSet::new();
    for digest in requests_by_url.values() {
        if !written.insert(*digest) {
            continue;
        }

        let path = bundle_manifest_path(bundle_root, digest);
        let mut file = std::fs::File::create(&path)?;

        if let Some(url) = source_url_by_digest.get(digest) {
            let source = store
                .get_source(url)
                .ok_or(Error::MissingManifest { digest: *digest })?
                .source;
            file.write_all(source.as_bytes())?;
            continue;
        }

        if let Some(manifest) = store.get(digest) {
            serde_json::to_writer(&mut file, manifest.as_ref())?;
            continue;
        }

        return Err(Error::MissingManifest { digest: *digest });
    }

    Ok(())
}

fn validate_bundle(index: &BundleIndex, bundle_root: &Path) -> Result<(), Error> {
    let mut validated = HashSet::new();
    for request in &index.requests {
        if !validated.insert(request.digest) {
            continue;
        }
        let path = bundle_manifest_path(bundle_root, &request.digest);
        let source: Arc<str> = std::fs::read_to_string(&path)?.into();
        let parsed = ParsedManifest::parse_named(request.url.as_str(), source)?;
        let actual = parsed.manifest.digest();
        if actual != request.digest {
            return Err(Error::MismatchedDigest {
                path,
                expected: request.digest,
                actual,
            });
        }
    }
    Ok(())
}

fn collect_bundle_schemes(requests_by_url: &HashMap<Url, ManifestDigest>) -> Vec<Arc<str>> {
    let mut schemes = BTreeSet::new();
    for url in requests_by_url.keys() {
        schemes.insert(url.scheme().to_string());
    }
    schemes.insert("file".to_string());
    schemes.insert("http".to_string());
    schemes.insert("https".to_string());
    schemes.into_iter().map(Arc::from).collect()
}

async fn load_bundle_registry(
    bundle_remote: &RemoteResolver,
    index: &BundleIndex,
) -> Result<ResolverRegistry, Error> {
    let mut registry = ResolverRegistry::new();
    let mut seen = HashSet::new();

    for request in &index.requests {
        let resolution = bundle_remote.resolve_url(&request.url).await?;
        for env in resolution.manifest.environments().values() {
            for resolver_name in &env.resolvers {
                if !seen.insert(resolver_name.clone()) {
                    continue;
                }
                registry.insert(resolver_name.clone(), bundle_remote.clone());
            }
        }
    }

    Ok(registry)
}

fn read_bundle_index(path: &Path) -> Result<BundleIndex, Error> {
    let bytes = std::fs::read(path)?;
    BundleIndex::from_bytes(&bytes)
}

fn maybe_read_bundle_index(path: &Path) -> Result<Option<BundleIndex>, Error> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    BundleIndex::maybe_from_bytes(&bytes)
}

fn bundle_root_for_index(path: &Path) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

fn bundle_manifest_path(bundle_root: &Path, digest: &ManifestDigest) -> PathBuf {
    let file_name = format!("{}.json5", digest_base64(digest));
    bundle_root.join(BUNDLE_MANIFEST_DIR).join(file_name)
}

fn digest_base64(digest: &ManifestDigest) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.bytes())
}
