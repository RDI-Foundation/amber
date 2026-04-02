#![allow(unused_assignments)]
#![allow(clippy::result_large_err)]

mod registry;
pub(crate) mod store;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use amber_manifest::{
    ChildTemplateAllowedManifests, ChildTemplateDecl, ComponentDecl, ExperimentalFeature, Manifest,
    ManifestDigest, ManifestRef,
};
use amber_resolver::{self as resolver, RemoteResolver, Resolver};
use futures::stream::StreamExt;
use miette::{Diagnostic, NamedSource, SourceSpan};
pub use registry::ResolverRegistry;
pub use store::DigestStore;
use thiserror::Error;
use tokio::sync::{OnceCell, Semaphore};
use url::Url;

use self::store::{StoredSource, display_url};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExperimentalFeatureList(Vec<ExperimentalFeature>);

impl fmt::Display for ExperimentalFeatureList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (idx, feature) in self.0.iter().enumerate() {
            if idx > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{feature}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Error, Diagnostic)]
#[error("{message}")]
#[diagnostic(severity(Advice))]
pub struct RelatedManifestSpan {
    message: String,
    #[source_code]
    src: NamedSource<Arc<str>>,
    #[label(primary, "{label}")]
    span: SourceSpan,
    label: String,
}

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

#[allow(unused_assignments)]
#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    #[diagnostic(transparent)]
    Resolver(#[from] resolver::Error),

    #[error("component tree contains a cycle: {cycle:?}")]
    #[diagnostic(code(compiler::cycle))]
    Cycle { cycle: Vec<Url> },

    #[error("relative manifest reference `{reference}` requires a file:// base URL")]
    #[diagnostic(code(compiler::relative_manifest_ref))]
    RelativeManifestRef { reference: Box<str> },

    #[error("invalid manifest reference `{reference}` in {realm_url}: {message}")]
    #[diagnostic(code(compiler::invalid_manifest_ref))]
    InvalidManifestRef {
        realm_url: Box<Url>,
        reference: Box<str>,
        message: Box<str>,
        #[source_code]
        src: Option<NamedSource<Arc<str>>>,
        #[label(primary, "invalid manifest reference")]
        span: Option<SourceSpan>,
    },

    #[error(
        "failed to resolve manifest reference `{reference}` for component `#{child}` in \
         {realm_path}: {message}"
    )]
    #[diagnostic(code(compiler::manifest_ref_resolution))]
    ManifestRefResolution {
        realm_path: Box<str>,
        child: Box<str>,
        reference: Box<str>,
        message: Box<str>,
        #[source_code]
        src: Option<NamedSource<Arc<str>>>,
        #[label(primary, "manifest reference declared here")]
        span: Option<SourceSpan>,
    },

    #[error(
        "unknown resolver `{resolver}` referenced by environment `{environment}` in {realm_url}"
    )]
    #[diagnostic(code(compiler::unknown_resolver))]
    UnknownResolver {
        realm_url: Box<Url>,
        environment: Box<str>,
        resolver: Box<str>,
        #[source_code]
        src: Option<NamedSource<Arc<str>>>,
        #[label(primary, "unknown resolver")]
        span: Option<SourceSpan>,
    },

    #[error(
        "component `#{child}` requests experimental feature(s) not enabled by its parent: \
         {missing_features}"
    )]
    #[diagnostic(
        code(compiler::experimental_feature_not_enabled),
        help(
            "Enable these features in the parent manifest's `experimental_features` list, or \
             remove them from the child manifest."
        )
    )]
    ExperimentalFeatureNotEnabled {
        child: Box<str>,
        missing_features: ExperimentalFeatureList,
        #[source_code]
        src: Option<NamedSource<Arc<str>>>,
        #[label(primary, "child declaration here")]
        span: Option<SourceSpan>,
        #[related]
        related: Vec<RelatedManifestSpan>,
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
    pub resolved_url: Url,
    pub observed_url: Option<Url>,
    pub config: Option<serde_json::Value>,
    pub children: BTreeMap<String, ResolvedNode>,
    pub child_templates: BTreeMap<String, ResolvedChildTemplate>,
}

#[derive(Clone, Debug)]
pub struct ResolvedChildTemplate {
    pub decl: ChildTemplateDecl,
    pub manifests: Vec<ResolvedTemplateManifest>,
}

#[derive(Clone, Debug)]
pub struct ResolvedTemplateManifest {
    pub source_ref: Url,
    pub root: ResolvedNode,
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
    resolved_url: Url,
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
    /// Per-compilation cache of resolved manifests, keyed by environment + URL.
    ///
    /// We intentionally do not cache by URL across compilations: URLs are mutable and not identity.
    /// Within a single compilation we assume a given URL is stable, so this memoizes successful
    /// resolutions and coalesces concurrent requests.
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

    let node = resolve_component(ctx, String::new(), root, None).await?;

    Ok(ResolvedTree { root: node })
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

    let resolved_ref = if !declared_ref.url.is_relative() {
        declared_ref.clone()
    } else {
        let Some(base) = base_url.as_ref() else {
            return Err(Error::RelativeManifestRef {
                reference: declared_ref.url.as_str().into(),
            });
        };
        if base.scheme() != "file" {
            return Err(Error::RelativeManifestRef {
                reference: declared_ref.url.as_str().into(),
            });
        }

        declared_ref.resolve_against(base).map_err(|err| {
            let (src, span) =
                svc.store
                    .diagnostic_source(base)
                    .map_or((None, None), |(src, spans)| {
                        let span = spans
                            .components
                            .get(name.as_str())
                            .and_then(|c| c.manifest)
                            .unwrap_or((0usize, 0usize).into());
                        (Some(src), Some(span))
                    });

            Error::InvalidManifestRef {
                realm_url: Box::new(base.clone()),
                reference: declared_ref.url.as_str().into(),
                message: err.to_string().into(),
                src,
                span,
            }
        })?
    };
    let resolved = match resolve_manifest(&svc, &env, &resolved_ref).await {
        Ok(resolved) => resolved,
        Err(err) if !name.is_empty() => {
            return Err(wrap_child_manifest_resolution_error(
                &svc,
                base_url.as_ref(),
                name.as_str(),
                &declared_ref,
                err,
            ));
        }
        Err(err) => return Err(err),
    };
    let ResolvedManifest {
        manifest,
        digest,
        resolved_url,
        observed_url,
    } = resolved;

    if path_set.contains(&digest) {
        stack.push(resolved_url.clone());
        return Err(Error::Cycle { cycle: stack });
    }
    path_set.insert(digest);
    stack.push(resolved_url.clone());

    let referenced_envs: HashSet<String> = manifest
        .components()
        .values()
        .filter_map(component_decl_environment)
        .collect();

    let realm_url = resolved_url.clone();
    let parent_features = manifest.experimental_features().clone();

    let mut env_cache: HashMap<String, Arc<ResolveEnv>> = HashMap::new();
    for env_name in &referenced_envs {
        let _ = compute_environment(&svc, &env, &manifest, &realm_url, env_name, &mut env_cache)?;
    }

    let children_futs: Vec<_> = manifest
        .components()
        .iter()
        .map(|(child_name, decl)| {
            let child_name = child_name.to_string();
            let (child_ref, child_cfg, child_env_name) = extract_component_decl(decl);
            let svc = Arc::clone(&svc);
            let parent_features = parent_features.clone();
            let child_stack = stack.clone();
            let child_path_set = path_set.clone();
            let realm_url = realm_url.clone();

            let child_env = match child_env_name {
                None => Arc::clone(&env),
                Some(env_name) => env_cache
                    .get(&env_name)
                    .cloned()
                    .expect("referenced environment should be precomputed"),
            };

            async move {
                let child_ctx = ResolveContext {
                    svc: Arc::clone(&svc),
                    env: child_env,
                    base_url: Some(realm_url.clone()),
                    stack: child_stack,
                    path_set: child_path_set,
                };
                let child_node =
                    resolve_component(child_ctx, child_name.clone(), child_ref, child_cfg).await?;
                validate_child_experimental_features(
                    &svc,
                    &realm_url,
                    child_name.as_str(),
                    &parent_features,
                    child_node.digest,
                    &child_node.resolved_url,
                )?;
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

    let child_templates = resolve_child_templates(
        &svc,
        &env,
        &manifest,
        &realm_url,
        &parent_features,
        &stack,
        &path_set,
    )
    .await?;

    Ok(ResolvedNode {
        name,
        declared_ref,
        digest,
        resolved_url,
        observed_url,
        config,
        children,
        child_templates,
    })
}

fn component_decl_environment(decl: &ComponentDecl) -> Option<String> {
    match decl {
        ComponentDecl::Object(o) => o.environment.clone(),
        ComponentDecl::Reference(_) => None,
        _ => None,
    }
}

fn child_manifest_decl_site(
    svc: &ResolveService,
    realm_url: &Url,
    child_name: &str,
) -> (Option<NamedSource<Arc<str>>>, Option<SourceSpan>) {
    svc.store
        .diagnostic_source(realm_url)
        .map_or((None, None), |(src, spans)| {
            let span = spans
                .components
                .get(child_name)
                .and_then(|component| component.manifest.or(Some(component.whole)))
                .unwrap_or((0usize, 0usize).into());
            (Some(src), Some(span))
        })
}

fn wrap_child_manifest_resolution_error(
    svc: &ResolveService,
    realm_url: Option<&Url>,
    child_name: &str,
    declared_ref: &ManifestRef,
    err: Error,
) -> Error {
    let Error::Resolver(resolver_err) = err else {
        return err;
    };
    if matches!(resolver_err, resolver::Error::Manifest(_)) {
        return Error::Resolver(resolver_err);
    }

    let Some(realm_url) = realm_url else {
        return Error::Resolver(resolver_err);
    };
    let (src, span) = child_manifest_decl_site(svc, realm_url, child_name);

    Error::ManifestRefResolution {
        realm_path: display_url(realm_url).into(),
        child: child_name.into(),
        reference: declared_ref.url.as_str().into(),
        message: resolver_error_message(&resolver_err).into(),
        src,
        span,
    }
}

fn resolver_error_message(err: &resolver::Error) -> String {
    match err {
        resolver::Error::Io(err) => err.to_string(),
        resolver::Error::Http(err) => err.to_string(),
        other => other.to_string(),
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

async fn resolve_child_templates(
    svc: &Arc<ResolveService>,
    env: &Arc<ResolveEnv>,
    manifest: &Manifest,
    realm_url: &Url,
    parent_features: &BTreeSet<ExperimentalFeature>,
    stack: &[Url],
    path_set: &HashSet<ManifestDigest>,
) -> Result<BTreeMap<String, ResolvedChildTemplate>, Error> {
    let mut out = BTreeMap::new();

    for (template_name, decl) in manifest.child_templates() {
        let refs = resolve_child_template_manifest_refs(realm_url, template_name.as_str(), decl)?;
        let mut manifests = Vec::with_capacity(refs.len());
        for reference in refs {
            let child_ctx = ResolveContext {
                svc: Arc::clone(svc),
                env: Arc::clone(env),
                base_url: Some(realm_url.clone()),
                stack: stack.to_vec(),
                path_set: path_set.clone(),
            };
            let root = Box::pin(resolve_component(
                child_ctx,
                String::new(),
                reference.clone(),
                None,
            ))
            .await?;
            validate_child_experimental_features(
                svc,
                realm_url,
                template_name.as_str(),
                parent_features,
                root.digest,
                &root.resolved_url,
            )?;
            manifests.push(ResolvedTemplateManifest {
                source_ref: root.resolved_url.clone(),
                root,
            });
        }

        manifests.sort_by(|left, right| left.source_ref.as_str().cmp(right.source_ref.as_str()));
        out.insert(
            template_name.to_string(),
            ResolvedChildTemplate {
                decl: decl.clone(),
                manifests,
            },
        );
    }

    Ok(out)
}

fn resolve_child_template_manifest_refs(
    realm_url: &Url,
    template_name: &str,
    decl: &ChildTemplateDecl,
) -> Result<Vec<ManifestRef>, Error> {
    match (&decl.manifest, &decl.allowed_manifests) {
        (Some(reference), None) => Ok(vec![resolve_manifest_ref_for_template(
            realm_url,
            template_name,
            reference,
        )?]),
        (None, Some(ChildTemplateAllowedManifests::Refs(refs))) => refs
            .iter()
            .map(|reference| resolve_manifest_ref_for_template(realm_url, template_name, reference))
            .collect(),
        (None, Some(ChildTemplateAllowedManifests::Selector(selector))) => {
            expand_child_template_selector(realm_url, template_name, selector)
        }
        (Some(_), Some(_)) | (None, None) | (None, Some(_)) => {
            unreachable!("manifest validation handles this")
        }
    }
}

fn resolve_manifest_ref_for_template(
    realm_url: &Url,
    template_name: &str,
    reference: &ManifestRef,
) -> Result<ManifestRef, Error> {
    if !reference.url.is_relative() {
        return Ok(reference.clone());
    }
    if realm_url.scheme() != "file" {
        return Err(Error::ManifestRefResolution {
            realm_path: display_url(realm_url).into(),
            child: template_name.into(),
            reference: reference.url.as_str().into(),
            message: "relative child template manifest references require a file:// owning \
                      manifest"
                .into(),
            src: None,
            span: None,
        });
    }
    reference
        .resolve_against(realm_url)
        .map_err(|err| Error::ManifestRefResolution {
            realm_path: display_url(realm_url).into(),
            child: template_name.into(),
            reference: reference.url.as_str().into(),
            message: err.to_string().into(),
            src: None,
            span: None,
        })
}

fn expand_child_template_selector(
    realm_url: &Url,
    template_name: &str,
    selector: &amber_manifest::ChildTemplateManifestSelector,
) -> Result<Vec<ManifestRef>, Error> {
    if realm_url.scheme() != "file" {
        return Err(Error::ManifestRefResolution {
            realm_path: display_url(realm_url).into(),
            child: template_name.into(),
            reference: selector.root.clone().into(),
            message: "allowed_manifests selectors require a file:// owning manifest".into(),
            src: None,
            span: None,
        });
    }

    let base_path = realm_url
        .to_file_path()
        .map_err(|_| Error::ManifestRefResolution {
            realm_path: display_url(realm_url).into(),
            child: template_name.into(),
            reference: selector.root.clone().into(),
            message: "owning manifest is not a filesystem path".into(),
            src: None,
            span: None,
        })?;
    let manifest_dir = base_path.parent().unwrap_or(Path::new("/"));
    let root_path = manifest_dir.join(&selector.root);
    let root_path =
        normalize_selector_root(&root_path).map_err(|message| Error::ManifestRefResolution {
            realm_path: display_url(realm_url).into(),
            child: template_name.into(),
            reference: selector.root.clone().into(),
            message: message.into(),
            src: None,
            span: None,
        })?;

    let include_patterns = if selector.include.is_empty() {
        vec!["**/*.json5".to_string()]
    } else {
        selector.include.clone()
    };
    let exclude_patterns = selector.exclude.clone();

    let mut matches = BTreeSet::new();
    for pattern in include_patterns {
        let absolute = root_path.join(pattern);
        let pattern = absolute.to_string_lossy().replace('\\', "/");
        for entry in glob::glob(&pattern).map_err(|err| Error::ManifestRefResolution {
            realm_path: display_url(realm_url).into(),
            child: template_name.into(),
            reference: selector.root.clone().into(),
            message: format!("invalid include glob `{}`: {err}", pattern).into(),
            src: None,
            span: None,
        })? {
            let path = entry.map_err(|err| Error::ManifestRefResolution {
                realm_path: display_url(realm_url).into(),
                child: template_name.into(),
                reference: selector.root.clone().into(),
                message: format!("failed to expand include glob: {err}").into(),
                src: None,
                span: None,
            })?;
            if path.is_file() {
                matches.insert(path);
            }
        }
    }

    for pattern in exclude_patterns {
        let absolute = root_path.join(pattern);
        let pattern = absolute.to_string_lossy().replace('\\', "/");
        for entry in glob::glob(&pattern).map_err(|err| Error::ManifestRefResolution {
            realm_path: display_url(realm_url).into(),
            child: template_name.into(),
            reference: selector.root.clone().into(),
            message: format!("invalid exclude glob `{}`: {err}", pattern).into(),
            src: None,
            span: None,
        })? {
            let path = entry.map_err(|err| Error::ManifestRefResolution {
                realm_path: display_url(realm_url).into(),
                child: template_name.into(),
                reference: selector.root.clone().into(),
                message: format!("failed to expand exclude glob: {err}").into(),
                src: None,
                span: None,
            })?;
            matches.remove(&path);
        }
    }

    let mut refs = Vec::with_capacity(matches.len());
    for path in matches {
        let url = Url::from_file_path(&path).map_err(|_| Error::ManifestRefResolution {
            realm_path: display_url(realm_url).into(),
            child: template_name.into(),
            reference: path.display().to_string().into(),
            message: "matched path is not representable as a file URL".into(),
            src: None,
            span: None,
        })?;
        refs.push(ManifestRef::from_url(url));
    }
    Ok(refs)
}

fn normalize_selector_root(root_path: &Path) -> Result<PathBuf, String> {
    if root_path.as_os_str().is_empty() {
        return Err("selector root must not be empty".to_string());
    }
    let root_path = if root_path.is_absolute() {
        root_path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|err| format!("failed to resolve selector root: {err}"))?
            .join(root_path)
    };
    if !root_path.exists() {
        return Err(format!(
            "selector root `{}` does not exist",
            root_path.display()
        ));
    }
    if !root_path.is_dir() {
        return Err(format!(
            "selector root `{}` is not a directory",
            root_path.display()
        ));
    }
    Ok(root_path)
}

fn validate_child_experimental_features(
    svc: &ResolveService,
    realm_url: &Url,
    child_name: &str,
    parent_features: &BTreeSet<ExperimentalFeature>,
    child_digest: ManifestDigest,
    child_url: &Url,
) -> Result<(), Error> {
    let child_manifest = svc
        .store
        .get(&child_digest)
        .expect("child manifest should be in the digest store after resolution");

    let missing_features = child_manifest
        .experimental_features()
        .difference(parent_features)
        .copied()
        .collect::<Vec<_>>();
    if missing_features.is_empty() {
        return Ok(());
    }

    let (src, span) =
        svc.store
            .diagnostic_source(realm_url)
            .map_or((None, None), |(src, spans)| {
                let span = spans
                    .components
                    .get(child_name)
                    .and_then(|component| component.manifest.or(Some(component.whole)))
                    .unwrap_or((0usize, 0usize).into());
                (Some(src), Some(span))
            });

    let mut related = Vec::new();
    if let Some(stored) = svc.store.get_source(child_url) {
        let span = stored
            .spans
            .experimental_features
            .or(stored.spans.manifest_version)
            .unwrap_or((0usize, 0usize).into());
        related.push(RelatedManifestSpan {
            message: format!("component `#{child_name}` requests these feature(s) here"),
            src: NamedSource::new(display_url(child_url), stored.source).with_language("json5"),
            span,
            label: "requested here".to_string(),
        });
    }

    Err(Error::ExperimentalFeatureNotEnabled {
        child: child_name.into(),
        missing_features: ExperimentalFeatureList(missing_features),
        src,
        span,
        related,
    })
}

fn compute_environment(
    svc: &ResolveService,
    base_env: &Arc<ResolveEnv>,
    manifest: &Manifest,
    realm_url: &Url,
    env_name: &str,
    env_cache: &mut HashMap<String, Arc<ResolveEnv>>,
) -> Result<Arc<ResolveEnv>, Error> {
    if let Some(e) = env_cache.get(env_name) {
        return Ok(Arc::clone(e));
    }

    let env_decl = manifest
        .environments()
        .get(env_name)
        .expect("environment names are validated in Manifest");

    let parent_env = if let Some(ext) = env_decl.extends.as_deref() {
        compute_environment(svc, base_env, manifest, realm_url, ext, env_cache)?
    } else {
        Arc::clone(base_env)
    };

    let mut remotes: Vec<RemoteResolver> = Vec::with_capacity(env_decl.resolvers.len());
    for resolver_name in &env_decl.resolvers {
        let Some(r) = svc.registry.get(resolver_name.as_str()) else {
            let (src, span) =
                svc.store
                    .diagnostic_source(realm_url)
                    .map_or((None, None), |(src, spans)| {
                        let env = spans.environments.get(env_name);
                        let span = env
                            .and_then(|e| {
                                e.resolvers
                                    .iter()
                                    .find(|(name, _)| name.as_ref() == resolver_name.as_str())
                                    .map(|(_, span)| *span)
                            })
                            .or_else(|| env.map(|e| e.name))
                            .unwrap_or((0usize, 0usize).into());
                        (Some(src), Some(span))
                    });
            return Err(Error::UnknownResolver {
                realm_url: Box::new(realm_url.clone()),
                environment: env_name.into(),
                resolver: resolver_name.as_str().into(),
                src,
                span,
            });
        };
        remotes.push(r);
    }

    if remotes.is_empty() {
        env_cache.insert(env_name.to_string(), Arc::clone(&parent_env));
        return Ok(parent_env);
    }

    let new_resolver = parent_env.resolver.as_ref().with_remotes(remotes);
    let id = EnvId(svc.next_env_id.fetch_add(1, Ordering::Relaxed));

    let out = Arc::new(ResolveEnv {
        id,
        resolver: Arc::new(new_resolver),
    });

    env_cache.insert(env_name.to_string(), Arc::clone(&out));
    Ok(out)
}

fn cached_manifest(svc: &ResolveService, r: &ManifestRef, url: &Url) -> Option<ResolvedManifest> {
    let expected = r.digest?;
    let manifest = svc.store.get(&expected)?;
    Some(ResolvedManifest {
        manifest,
        digest: expected,
        resolved_url: url.clone(),
        observed_url: None,
    })
}

async fn resolve_manifest(
    svc: &ResolveService,
    env: &ResolveEnv,
    r: &ManifestRef,
) -> Result<ResolvedManifest, Error> {
    let url = r
        .url
        .as_url()
        .expect("resolved manifest ref should be absolute");
    if let Some(resolved) = cached_manifest(svc, r, url) {
        return Ok(resolved);
    }

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
        return Err(Error::Resolver(resolver::Error::MismatchedDigest(
            url.clone(),
        )));
    }

    Ok(resolved)
}

async fn resolve_manifest_inner(
    svc: &ResolveService,
    env: &ResolveEnv,
    r: &ManifestRef,
) -> Result<ResolvedManifest, Error> {
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
    if let Some(resolved) = cached_manifest(svc, r, url) {
        return Ok(resolved);
    }
    let resolution = env.resolver.resolve(url, r.digest).await?;
    let manifest = Arc::new(resolution.manifest);
    let digest = manifest.digest();
    let stored = svc.store.put(digest, manifest);

    let observed_url = (resolution.url != *url).then_some(resolution.url);
    let source_record = StoredSource {
        digest,
        source: resolution.source,
        spans: resolution.spans,
        bundle_source: resolution.bundle_source,
    };
    svc.store.put_source(url.clone(), source_record);

    Ok(ResolvedManifest {
        manifest: stored,
        digest,
        resolved_url: url.clone(),
        observed_url,
    })
}
