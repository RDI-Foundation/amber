use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

use amber_manifest::{ComponentDecl, Manifest, ManifestDigest, ManifestRef};
use amber_resolver::{self as resolver, Cache, Resolver};
use futures::stream::StreamExt;
use tokio::sync::{OnceCell, Semaphore};
use url::Url;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolveMode {
    Online,
    Offline,
}

#[derive(Clone, Debug)]
pub struct ResolveOptions {
    pub mode: ResolveMode,
    pub max_concurrency: usize,
}

impl Default for ResolveOptions {
    fn default() -> Self {
        Self {
            mode: ResolveMode::Online,
            max_concurrency: 64,
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Resolver(#[from] resolver::Error),
    #[error("offline mode: manifest not found in cache: {0}")]
    OfflineMiss(Url),
    #[error("component tree contains a cycle: {cycle:?}")]
    Cycle { cycle: Vec<Url> },
}

#[derive(Clone, Debug)]
pub struct ResolvedTree {
    pub root: ResolvedNode,
}

#[derive(Clone, Debug)]
pub struct ResolvedNode {
    pub name: String,
    pub declared_ref: ManifestRef,
    pub resolved_url: Url,
    pub digest: ManifestDigest,
    pub manifest: Arc<Manifest>,
    pub config: Option<serde_json::Value>,
    pub children: BTreeMap<String, ResolvedNode>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum ResolveKey {
    Digest(ManifestDigest),
    Url(Url),
}

impl ResolveKey {
    fn from_ref(r: &ManifestRef) -> Self {
        if let Some(d) = &r.digest {
            ResolveKey::Digest(*d)
        } else {
            ResolveKey::Url(r.url.clone())
        }
    }
}

#[derive(Clone)]
struct ResolveService {
    resolver: Resolver,
    cache: Cache,
    mode: ResolveMode,
    max_concurrency: usize,
    sem: Arc<Semaphore>,
    inflight: Arc<dashmap::DashMap<ResolveKey, Arc<OnceCell<ResolvedManifest>>>>,
}

#[derive(Clone, Debug)]
struct ResolvedManifest {
    manifest: Arc<Manifest>,
    resolved_url: Url,
    digest: ManifestDigest,
}

pub async fn resolve_tree(
    resolver: Resolver,
    cache: Cache,
    root: ManifestRef,
    opts: ResolveOptions,
) -> Result<ResolvedTree, Error> {
    let max = opts.max_concurrency.max(1);
    let svc = ResolveService {
        resolver,
        cache,
        mode: opts.mode,
        max_concurrency: max,
        sem: Arc::new(Semaphore::new(max)),
        inflight: Arc::new(dashmap::DashMap::new()),
    };

    let node = resolve_component(
        &svc,
        "root".to_string(),
        root,
        None,
        Vec::new(),
        HashSet::new(),
    )
    .await?;
    Ok(ResolvedTree { root: node })
}

async fn resolve_component(
    svc: &ResolveService,
    name: String,
    declared_ref: ManifestRef,
    config: Option<serde_json::Value>,
    mut stack: Vec<Url>,
    mut path_set: HashSet<ManifestDigest>,
) -> Result<ResolvedNode, Error> {
    // Resolve first so we can detect cycles by stable identity (digest), even across URL aliasing.
    let resolved = resolve_manifest(svc, &declared_ref).await?;
    let ResolvedManifest {
        manifest,
        resolved_url,
        digest,
    } = resolved;

    // Cycle detection by digest along the current path.
    if path_set.contains(&digest) {
        stack.push(declared_ref.url.clone());
        return Err(Error::Cycle { cycle: stack });
    }
    path_set.insert(digest);
    stack.push(declared_ref.url.clone());

    let children = {
        let children_iter = manifest.components.iter().map(|(child_name, decl)| {
            let child_name = child_name.clone();
            let (child_ref, child_cfg) = extract_component_decl(decl);
            let svc = svc.clone();
            let child_stack = stack.clone();
            let child_path_set = path_set.clone();

            async move {
                let child_node = resolve_component(
                    &svc,
                    child_name.clone(),
                    child_ref,
                    child_cfg,
                    child_stack,
                    child_path_set,
                )
                .await?;
                Ok::<(String, ResolvedNode), Error>((child_name, child_node))
            }
        });

        let mut children_stream =
            futures::stream::iter(children_iter).buffer_unordered(svc.max_concurrency);

        let mut children = BTreeMap::new();
        while let Some(res) = children_stream.next().await {
            let (child_name, child_node) = res?;
            children.insert(child_name, child_node);
        }
        children
    };

    Ok(ResolvedNode {
        name,
        declared_ref,
        resolved_url,
        digest,
        manifest,
        config,
        children,
    })
}

fn extract_component_decl(decl: &ComponentDecl) -> (ManifestRef, Option<serde_json::Value>) {
    match decl {
        ComponentDecl::Reference(r) => (r.clone(), None),
        ComponentDecl::Object(o) => (o.manifest.clone(), o.config.clone()),
        _ => unreachable!("unsupported component declaration"),
    }
}

async fn resolve_manifest(
    svc: &ResolveService,
    r: &ManifestRef,
) -> Result<ResolvedManifest, Error> {
    let key = ResolveKey::from_ref(r);
    let cell = svc
        .inflight
        .entry(key)
        .or_insert_with(|| Arc::new(OnceCell::new()))
        .clone();

    let resolved = cell
        .get_or_try_init(|| async { resolve_manifest_inner(svc, r).await })
        .await?;

    Ok(resolved.clone())
}

async fn resolve_manifest_inner(
    svc: &ResolveService,
    r: &ManifestRef,
) -> Result<ResolvedManifest, Error> {
    // Cache first (both modes).
    if let Some(expected) = &r.digest {
        if let Some(entry) = svc.cache.get_by_digest(expected) {
            return Ok(ResolvedManifest {
                digest: *expected,
                resolved_url: entry.resolved_url,
                manifest: entry.manifest,
            });
        }

        if let Some(entry) = svc.cache.get_by_url(&r.url) {
            let actual = entry.manifest.digest();
            if actual == *expected {
                return Ok(ResolvedManifest {
                    digest: actual,
                    resolved_url: entry.resolved_url,
                    manifest: entry.manifest,
                });
            }

            // Cache contains an entry for the URL, but it does not match the pinned digest.
            // - Offline: hard error.
            // - Online: treat as a miss and re-resolve from the source (with digest verification).
            if svc.mode == ResolveMode::Offline {
                return Err(resolver::Error::MismatchedDigest(entry.resolved_url).into());
            }
        }
    } else if let Some(entry) = svc.cache.get_by_url(&r.url) {
        return Ok(ResolvedManifest {
            digest: entry.manifest.digest(),
            resolved_url: entry.resolved_url,
            manifest: entry.manifest,
        });
    }

    // Offline: no fallback.
    if svc.mode == ResolveMode::Offline {
        return Err(Error::OfflineMiss(r.url.clone()));
    }

    // Online: resolve (concurrency-limited).
    let _permit = svc.sem.acquire().await.expect("semaphore closed");

    let resolution = svc.resolver.resolve(&r.url, r.digest).await?;
    let manifest = Arc::new(resolution.manifest);
    let digest = manifest.digest();

    // Alias both declared URL and resolved URL to the same manifest content.
    svc.cache.put_arc(
        resolution.url.clone(),
        resolution.url.clone(),
        Arc::clone(&manifest),
    );
    svc.cache
        .put_arc(r.url.clone(), resolution.url.clone(), Arc::clone(&manifest));

    Ok(ResolvedManifest {
        manifest,
        digest,
        resolved_url: resolution.url,
    })
}
