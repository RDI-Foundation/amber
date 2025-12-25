use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use amber_manifest::{ComponentDecl, Manifest, ManifestDigest, ManifestRef};
use amber_resolver::{self as resolver, RemoteResolver, Resolver};
use futures::stream::StreamExt;
use tokio::sync::{OnceCell, Semaphore};
use url::Url;

use crate::{DigestStore, ResolverRegistry};

#[derive(Clone, Debug)]
pub struct ResolveOptions {
    pub max_concurrency: usize,
}

impl Default for ResolveOptions {
    fn default() -> Self {
        Self {
            max_concurrency: 64,
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Resolver(#[from] resolver::Error),
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
    pub digest: ManifestDigest,
    pub observed_url: Option<Url>,
    pub config: Option<serde_json::Value>,
    pub children: BTreeMap<String, ResolvedNode>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct EnvId(u32);

#[derive(Clone)]
struct ResolveEnv {
    id: EnvId,
    resolver: Arc<Resolver>,
}

impl ResolveEnv {
    fn root(resolver: Resolver) -> Self {
        Self {
            id: EnvId(0),
            resolver: Arc::new(resolver),
        }
    }
}

#[derive(Clone, Debug)]
struct ResolvedManifest {
    manifest: Arc<Manifest>,
    digest: ManifestDigest,
    observed_url: Option<Url>,
}

struct ResolveService {
    store: DigestStore,
    max_concurrency: usize,
    sem: Arc<Semaphore>,
    inflight: dashmap::DashMap<(EnvId, Url), Arc<OnceCell<ResolvedManifest>>>,
    registry: ResolverRegistry,
    next_env_id: AtomicU32,
}

pub async fn resolve_tree(
    resolver: Resolver,
    store: DigestStore,
    registry: ResolverRegistry,
    root: ManifestRef,
    opts: ResolveOptions,
) -> Result<ResolvedTree, Error> {
    let max = opts.max_concurrency.max(1);
    let svc = Arc::new(ResolveService {
        store,
        max_concurrency: max,
        sem: Arc::new(Semaphore::new(max)),
        inflight: dashmap::DashMap::new(),
        registry,
        next_env_id: AtomicU32::new(1),
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
    let resolved = resolve_manifest(&svc, &env, &declared_ref).await?;
    let ResolvedManifest {
        manifest,
        digest,
        observed_url,
    } = resolved;

    if path_set.contains(&digest) {
        stack.push(declared_ref.url.clone());
        return Err(Error::Cycle { cycle: stack });
    }
    path_set.insert(digest);
    stack.push(declared_ref.url.clone());

    let referenced_envs: HashSet<String> = manifest
        .components
        .values()
        .filter_map(component_decl_environment)
        .collect();

    let realm_url = observed_url.as_ref().unwrap_or(&declared_ref.url);

    let mut env_cache: HashMap<String, Arc<ResolveEnv>> = HashMap::new();
    for env_name in &referenced_envs {
        let _ = compute_environment(
            &svc,
            &env,
            &manifest,
            realm_url,
            env_name,
            &mut env_cache,
            &mut HashSet::new(),
        )?;
    }

    let children_futs: Vec<_> = manifest
        .components
        .iter()
        .map(|(child_name, decl)| {
            let child_name = child_name.clone();
            let (child_ref, child_cfg, child_env_name) = extract_component_decl(decl);
            let svc = Arc::clone(&svc);
            let child_stack = stack.clone();
            let child_path_set = path_set.clone();

            let child_env = match child_env_name {
                None => Arc::clone(&env),
                Some(env_name) => env_cache
                    .get(&env_name)
                    .cloned()
                    .unwrap_or_else(|| Arc::clone(&env)),
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
        })
        .collect();

    let mut children_stream =
        futures::stream::iter(children_futs).buffer_unordered(svc.max_concurrency);

    let mut children = BTreeMap::new();
    while let Some(res) = children_stream.next().await {
        let (child_name, child_node) = res?;
        children.insert(child_name, child_node);
    }

    Ok(ResolvedNode {
        name,
        declared_ref,
        digest,
        observed_url,
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

    if !visiting.insert(env_name.to_string()) {
        return Ok(Arc::clone(base_env));
    }

    let Some(env_decl) = manifest.environments.get(env_name) else {
        visiting.remove(env_name);
        return Ok(Arc::clone(base_env));
    };

    let parent_env = if let Some(ext) = env_decl.extends.as_deref() {
        compute_environment(svc, base_env, manifest, realm_url, ext, env_cache, visiting)?
    } else {
        Arc::clone(base_env)
    };

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

    if remotes.is_empty() {
        env_cache.insert(env_name.to_string(), Arc::clone(&parent_env));
        visiting.remove(env_name);
        return Ok(parent_env);
    }

    let new_resolver = parent_env.resolver.as_ref().with_remotes(remotes);
    let id = EnvId(svc.next_env_id.fetch_add(1, Ordering::Relaxed));

    let out = Arc::new(ResolveEnv {
        id,
        resolver: Arc::new(new_resolver),
    });

    env_cache.insert(env_name.to_string(), Arc::clone(&out));
    visiting.remove(env_name);
    Ok(out)
}

async fn resolve_manifest(
    svc: &ResolveService,
    env: &ResolveEnv,
    r: &ManifestRef,
) -> Result<ResolvedManifest, Error> {
    if let Some(expected) = r.digest
        && let Some(manifest) = svc.store.get(&expected)
    {
        return Ok(ResolvedManifest {
            manifest,
            digest: expected,
            observed_url: None,
        });
    }

    let key = (env.id, r.url.clone());
    let cell = svc
        .inflight
        .entry(key)
        .or_insert_with(|| Arc::new(OnceCell::new()))
        .clone();

    let resolved = cell
        .get_or_try_init(|| async { resolve_manifest_inner(svc, env, r).await })
        .await?
        .clone();

    if let Some(expected) = r.digest
        && resolved.digest != expected
    {
        let url = resolved
            .observed_url
            .clone()
            .unwrap_or_else(|| r.url.clone());
        return Err(Error::Resolver(resolver::Error::MismatchedDigest(url)));
    }

    Ok(resolved)
}

async fn resolve_manifest_inner(
    svc: &ResolveService,
    env: &ResolveEnv,
    r: &ManifestRef,
) -> Result<ResolvedManifest, Error> {
    if let Some(expected) = r.digest
        && let Some(manifest) = svc.store.get(&expected)
    {
        return Ok(ResolvedManifest {
            manifest,
            digest: expected,
            observed_url: None,
        });
    }

    let _permit = svc
        .sem
        .clone()
        .acquire_owned()
        .await
        .expect("semaphore closed");

    let resolution = env.resolver.resolve(&r.url, r.digest).await?;
    let manifest = Arc::new(resolution.manifest);
    let digest = manifest.digest();
    let stored = svc.store.put(digest, manifest);

    let observed_url = (resolution.url != r.url).then_some(resolution.url);

    Ok(ResolvedManifest {
        manifest: stored,
        digest,
        observed_url,
    })
}
