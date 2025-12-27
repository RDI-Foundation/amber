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

    #[error("relative manifest reference `{reference}` requires an absolute base URL")]
    RelativeManifestRef { reference: Box<str> },

    #[error("invalid manifest reference `{reference}` in {realm_url}: {message}")]
    InvalidManifestRef {
        realm_url: Box<Url>,
        reference: Box<str>,
        message: Box<str>,
    },

    #[error(
        "unknown resolver `{resolver}` referenced by environment `{environment}` in {realm_url}"
    )]
    UnknownResolver {
        realm_url: Box<Url>,
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

struct ResolveContext {
    svc: Arc<ResolveService>,
    env: Arc<ResolveEnv>,
    base_url: Option<Url>,
    stack: Vec<Url>,
    path_set: HashSet<ManifestDigest>,
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

    let ctx = ResolveContext {
        svc: Arc::clone(&svc),
        env: root_env,
        base_url: None,
        stack: Vec::new(),
        path_set: HashSet::new(),
    };

    let node = resolve_component(ctx, "root".to_string(), root, None).await?;

    Ok(ResolvedTree { root: node })
}

fn resolve_manifest_ref(
    declared_ref: &ManifestRef,
    base_url: Option<&Url>,
) -> Result<ManifestRef, Error> {
    if !declared_ref.url.is_relative() {
        return Ok(declared_ref.clone());
    }

    let Some(base) = base_url else {
        return Err(Error::RelativeManifestRef {
            reference: declared_ref.url.as_str().into(),
        });
    };

    declared_ref
        .resolve_against(base)
        .map_err(|err| Error::InvalidManifestRef {
            realm_url: Box::new(base.clone()),
            reference: declared_ref.url.as_str().into(),
            message: err.to_string().into(),
        })
}

async fn resolve_component(
    ctx: ResolveContext,
    name: String,
    declared_ref: ManifestRef,
    config: Option<serde_json::Value>,
) -> Result<ResolvedNode, Error> {
    let ResolveContext {
        svc,
        env,
        base_url,
        mut stack,
        mut path_set,
    } = ctx;
    let resolved_ref = resolve_manifest_ref(&declared_ref, base_url.as_ref())?;
    let resolved = resolve_manifest(&svc, &env, &resolved_ref).await?;
    let ResolvedManifest {
        manifest,
        digest,
        observed_url,
    } = resolved;

    if path_set.contains(&digest) {
        let resolved_url = resolved_ref
            .url
            .as_url()
            .expect("resolved manifest ref should be absolute");
        stack.push(resolved_url.clone());
        return Err(Error::Cycle { cycle: stack });
    }
    path_set.insert(digest);
    let resolved_url = resolved_ref
        .url
        .as_url()
        .expect("resolved manifest ref should be absolute");
    stack.push(resolved_url.clone());

    let referenced_envs: HashSet<String> = manifest
        .components()
        .values()
        .filter_map(component_decl_environment)
        .collect();

    let realm_url = observed_url.as_ref().unwrap_or(resolved_url).clone();

    let mut env_cache: HashMap<String, Arc<ResolveEnv>> = HashMap::new();
    for env_name in &referenced_envs {
        let _ = compute_environment(
            &svc,
            &env,
            &manifest,
            &realm_url,
            env_name,
            &mut env_cache,
            &mut HashSet::new(),
        )?;
    }

    let children_futs: Vec<_> = manifest
        .components()
        .iter()
        .map(|(child_name, decl)| {
            let child_name = child_name.to_string();
            let (child_ref, child_cfg, child_env_name) = extract_component_decl(decl);
            let svc = Arc::clone(&svc);
            let child_stack = stack.clone();
            let child_path_set = path_set.clone();
            let realm_url = realm_url.clone();

            let child_env = match child_env_name {
                None => Arc::clone(&env),
                Some(env_name) => env_cache
                    .get(&env_name)
                    .cloned()
                    .unwrap_or_else(|| Arc::clone(&env)),
            };

            async move {
                let child_ctx = ResolveContext {
                    svc,
                    env: child_env,
                    base_url: Some(realm_url),
                    stack: child_stack,
                    path_set: child_path_set,
                };
                let child_node =
                    resolve_component(child_ctx, child_name.clone(), child_ref, child_cfg).await?;
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

    let Some(env_decl) = manifest.environments().get(env_name) else {
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
                realm_url: Box::new(realm_url.clone()),
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

    let url = r
        .url
        .as_url()
        .expect("resolved manifest ref should be absolute");
    let key = (env.id, url.clone());
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
        let url = resolved.observed_url.clone().unwrap_or_else(|| url.clone());
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

    let url = r
        .url
        .as_url()
        .expect("resolved manifest ref should be absolute");
    let resolution = env.resolver.resolve(url, r.digest).await?;
    let manifest = Arc::new(resolution.manifest);
    let digest = manifest.digest();
    let stored = svc.store.put(digest, manifest);

    let observed_url = (resolution.url != *url).then_some(resolution.url);

    Ok(ResolvedManifest {
        manifest: stored,
        digest,
        observed_url,
    })
}
