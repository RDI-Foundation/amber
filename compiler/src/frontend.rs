use std::{
    collections::{BTreeMap, HashMap, HashSet},
    hash::{Hash as _, Hasher as _},
    sync::Arc,
};

use amber_manifest::{ComponentDecl, Manifest, ManifestDigest, ManifestRef};
use amber_resolver::{self as resolver, Cache, CacheScope, RemoteResolver, Resolver};
use futures::stream::StreamExt;
use tokio::sync::{OnceCell, Semaphore};
use url::Url;

use crate::ResolverRegistry;

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

    #[error(
        "unknown resolver `{resolver}` referenced by environment `{environment}` in {realm_url}"
    )]
    UnknownResolver {
        realm_url: Url,
        environment: Box<str>,
        resolver: Box<str>,
    },
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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct InflightKey {
    scope: CacheScope,
    key: ResolveKey,
}

#[derive(Clone)]
struct ResolveEnv {
    scope: CacheScope,
    resolver: Arc<Resolver>,
}

impl ResolveEnv {
    fn root(resolver: Resolver) -> Self {
        Self {
            scope: CacheScope::DEFAULT,
            resolver: Arc::new(resolver),
        }
    }
}

struct ResolveService {
    cache: Cache,
    mode: ResolveMode,
    max_concurrency: usize,
    sem: Arc<Semaphore>,
    inflight: dashmap::DashMap<InflightKey, Arc<OnceCell<ResolvedManifest>>>,
    registry: ResolverRegistry,
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
    registry: ResolverRegistry,
    root: ManifestRef,
    opts: ResolveOptions,
) -> Result<ResolvedTree, Error> {
    let max = opts.max_concurrency.max(1);
    let svc = Arc::new(ResolveService {
        cache,
        mode: opts.mode,
        max_concurrency: max,
        sem: Arc::new(Semaphore::new(max)),
        inflight: dashmap::DashMap::new(),
        registry,
    });

    let root_env = Arc::new(ResolveEnv::root(resolver));

    let node = resolve_component(
        Arc::clone(&svc),
        root_env,
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
    svc: Arc<ResolveService>,
    env: Arc<ResolveEnv>,
    name: String,
    declared_ref: ManifestRef,
    config: Option<serde_json::Value>,
    mut stack: Vec<Url>,
    mut path_set: HashSet<ManifestDigest>,
) -> Result<ResolvedNode, Error> {
    // Resolve first so we can detect cycles by stable identity (digest), even across URL aliasing.
    let resolved = resolve_manifest(&svc, &env, &declared_ref).await?;
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

    // Build only the environments that are actually referenced by children in this realm.
    let referenced_envs: HashSet<String> = manifest
        .components
        .values()
        .filter_map(component_decl_environment)
        .collect();

    let mut env_cache: HashMap<String, Arc<ResolveEnv>> = HashMap::new();
    for env_name in &referenced_envs {
        // Populate env_cache (memoized) so child resolution is cheap.
        let _ = compute_environment(
            &svc,
            &env,
            &manifest,
            &resolved_url,
            env_name,
            &mut env_cache,
            &mut HashSet::new(),
        )?;
    }

    let children = {
        let children_iter = manifest.components.iter().map(|(child_name, decl)| {
            let child_name = child_name.clone();
            let (child_ref, child_cfg, child_env_name) = extract_component_decl(decl);
            let svc = Arc::clone(&svc);
            let child_stack = stack.clone();
            let child_path_set = path_set.clone();

            let child_env = match child_env_name {
                None => Arc::clone(&env),
                Some(env_name) => env_cache.get(&env_name).cloned().unwrap_or_else(|| {
                    // Manifest validation ensures the env exists; if it doesn't, fall back to base.
                    // Resolution will likely fail later with UnsupportedScheme anyway.
                    Arc::clone(&env)
                }),
            };

            async move {
                let child_node = resolve_component(
                    svc,
                    child_env,
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

fn component_decl_environment(decl: &ComponentDecl) -> Option<String> {
    match decl {
        ComponentDecl::Object(o) => o.environment.clone(),
        ComponentDecl::Reference(_) => None,
        _ => None,
    }
}

fn extract_component_decl(
    decl: &ComponentDecl,
) -> (ManifestRef, Option<serde_json::Value>, Option<String>) {
    match decl {
        ComponentDecl::Reference(r) => (r.clone(), None, None),
        ComponentDecl::Object(o) => (o.manifest.clone(), o.config.clone(), o.environment.clone()),
        _ => unreachable!("unsupported component declaration"),
    }
}

/// Compute a child resolution environment (memoized by `env_cache`) for a named environment.
///
/// Semantics:
/// - `base_env` is the realm's inherited environment (the one used to resolve this realm).
/// - A named environment extends either:
///   - `base_env` (if `extends` is None), or
///   - another named environment (within this manifest), recursively.
/// - The environment adds remote resolvers by name (looked up via the host registry).
///
/// Performance:
/// - Memoized per realm instance, per referenced name.
/// - Adds all remotes in one `Resolver::with_remotes` call to avoid repeated cloning.
fn compute_environment(
    svc: &ResolveService,
    base_env: &Arc<ResolveEnv>,
    manifest: &Manifest,
    realm_url: &Url,
    env_name: &str,
    env_cache: &mut HashMap<String, Arc<ResolveEnv>>,
    visiting: &mut HashSet<String>,
) -> Result<Arc<ResolveEnv>, Error> {
    if let Some(e) = env_cache.get(env_name) {
        return Ok(Arc::clone(e));
    }

    // Defensive cycle check; RawManifest validation should already reject this.
    if !visiting.insert(env_name.to_string()) {
        // Fall back to base env; cycle is a manifest bug.
        return Ok(Arc::clone(base_env));
    }

    let Some(env_decl) = manifest.environments.get(env_name) else {
        // Manifest validation should prevent this; just fall back.
        visiting.remove(env_name);
        return Ok(Arc::clone(base_env));
    };

    let parent_env = if let Some(ext) = env_decl.extends.as_deref() {
        compute_environment(svc, base_env, manifest, realm_url, ext, env_cache, visiting)?
    } else {
        Arc::clone(base_env)
    };

    // Translate resolver names into actual remote resolvers using the registry.
    let mut remotes: Vec<RemoteResolver> = Vec::with_capacity(env_decl.resolvers.len());
    for resolver_name in &env_decl.resolvers {
        let Some(r) = svc.registry.get(resolver_name.as_str()) else {
            return Err(Error::UnknownResolver {
                realm_url: realm_url.clone(),
                environment: env_name.into(),
                resolver: resolver_name.as_str().into(),
            });
        };
        remotes.push(r);
    }

    // If this environment adds nothing, treat it as an alias for its parent environment.
    if remotes.is_empty() {
        env_cache.insert(env_name.to_string(), Arc::clone(&parent_env));
        visiting.remove(env_name);
        return Ok(parent_env);
    }

    let scope = derive_scope(parent_env.scope, env_name, &env_decl.resolvers);
    let new_resolver = parent_env.resolver.as_ref().with_remotes(remotes);

    let out = Arc::new(ResolveEnv {
        scope,
        resolver: Arc::new(new_resolver),
    });

    env_cache.insert(env_name.to_string(), Arc::clone(&out));
    visiting.remove(env_name);
    Ok(out)
}

fn derive_scope(base: CacheScope, env_name: &str, resolver_names: &[String]) -> CacheScope {
    // Must be deterministic within a process; does not need to be stable across processes
    // until the cache becomes persistent.
    let mut h = std::collections::hash_map::DefaultHasher::new();
    "amber-env-v1".hash(&mut h);
    base.id().hash(&mut h);
    env_name.hash(&mut h);
    for r in resolver_names {
        r.hash(&mut h);
    }
    CacheScope::new(h.finish())
}

async fn resolve_manifest(
    svc: &ResolveService,
    env: &ResolveEnv,
    r: &ManifestRef,
) -> Result<ResolvedManifest, Error> {
    let key = InflightKey {
        scope: env.scope,
        key: ResolveKey::from_ref(r),
    };

    let cell = svc
        .inflight
        .entry(key)
        .or_insert_with(|| Arc::new(OnceCell::new()))
        .clone();

    let resolved = cell
        .get_or_try_init(|| async { resolve_manifest_inner(svc, env, r).await })
        .await?;

    Ok(resolved.clone())
}

async fn resolve_manifest_inner(
    svc: &ResolveService,
    env: &ResolveEnv,
    r: &ManifestRef,
) -> Result<ResolvedManifest, Error> {
    // Cache first (both modes).
    if let Some(expected) = &r.digest {
        let mut mismatched_url: Option<Url> = None;

        // URL cache is scoped (environment-specific) and preserves per-reference provenance.
        if let Some(entry) = svc.cache.get_by_url_scoped(env.scope, &r.url) {
            let actual = entry.manifest.digest();
            if actual == *expected {
                return Ok(ResolvedManifest {
                    digest: actual,
                    resolved_url: entry.resolved_url,
                    manifest: entry.manifest,
                });
            }
            mismatched_url = Some(entry.resolved_url);
        }

        // Digest cache is global (safe across environments).
        if let Some(entry) = svc.cache.get_by_digest(expected) {
            return Ok(ResolvedManifest {
                digest: *expected,
                resolved_url: entry.resolved_url,
                manifest: entry.manifest,
            });
        }

        if svc.mode == ResolveMode::Offline {
            if let Some(resolved_url) = mismatched_url {
                return Err(resolver::Error::MismatchedDigest(resolved_url).into());
            }
            return Err(Error::OfflineMiss(r.url.clone()));
        }
    } else if let Some(entry) = svc.cache.get_by_url_scoped(env.scope, &r.url) {
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

    let resolution = env.resolver.resolve(&r.url, r.digest).await?;
    let manifest = Arc::new(resolution.manifest);
    let digest = manifest.digest();

    // Alias both declared URL and resolved URL to the same manifest content, in this environment scope.
    svc.cache.put_arc_scoped(
        env.scope,
        resolution.url.clone(),
        resolution.url.clone(),
        Arc::clone(&manifest),
    );
    svc.cache.put_arc_scoped(
        env.scope,
        r.url.clone(),
        resolution.url.clone(),
        Arc::clone(&manifest),
    );

    Ok(ResolvedManifest {
        manifest,
        digest,
        resolved_url: resolution.url,
    })
}
