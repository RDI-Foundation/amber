#![allow(unused_assignments)]
#![allow(clippy::result_large_err)]

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

use amber_manifest::{
    BindingSource, BindingTarget, BindingTargetKey, CapabilityDecl, ChildName, ExportName,
    ExportTarget, Manifest, ManifestDigest,
};
use amber_scenario::{
    BindingEdge, Component, ComponentId, ProvideRef, Scenario, SlotRef, graph::component_path_for,
};
use jsonschema::Validator;
use miette::{Diagnostic, NamedSource, SourceSpan};
use serde_json::{Map, Value};
use thiserror::Error;

use super::frontend::{ResolvedNode, ResolvedTree};
use crate::{ComponentProvenance, DigestStore, Provenance, RootExportProvenance};

#[allow(unused_assignments)]
#[derive(Debug, Error, Diagnostic)]
#[error("{message}")]
#[diagnostic(severity(Advice))]
pub struct RelatedSpan {
    message: String,
    #[source_code]
    src: NamedSource<Arc<str>>,
    #[label(primary, "{label}")]
    span: SourceSpan,
    label: String,
}

fn describe_component_path(path: &str) -> String {
    if path == "/" {
        "root component".to_string()
    } else {
        format!("component {path}")
    }
}

fn source_for_component(
    provenance: &Provenance,
    store: &DigestStore,
    id: ComponentId,
) -> Option<(NamedSource<Arc<str>>, Arc<amber_manifest::ManifestSpans>)> {
    let url = provenance.for_component(id).effective_url();
    store.diagnostic_source(url)
}

fn unknown_source() -> NamedSource<Arc<str>> {
    NamedSource::new("<source unavailable>", Arc::from("")).with_language("json5")
}

fn component_decl_site(
    components: &[Component],
    provenance: &Provenance,
    store: &DigestStore,
    id: ComponentId,
) -> Option<RelatedSpan> {
    let component = &components[id.0];
    let parent = component.parent?;
    let (src, spans) = source_for_component(provenance, store, parent)?;
    let span = spans.components.get(component.name.as_str())?.name;
    let parent_path = describe_component_path(&component_path_for(components, parent));
    Some(RelatedSpan {
        message: format!("component `{}` declared on {}", component.name, parent_path),
        src,
        span,
        label: "component declared here".to_string(),
    })
}

fn binding_target_site(
    provenance: &Provenance,
    store: &DigestStore,
    realm: ComponentId,
    target_key: &BindingTargetKey,
) -> Option<(NamedSource<Arc<str>>, SourceSpan)> {
    let (src, spans) = source_for_component(provenance, store, realm)?;
    let span = spans
        .bindings
        .get(target_key)
        .map(|b| b.slot.or(b.to).unwrap_or(b.whole))
        .unwrap_or((0usize, 0usize).into());
    Some((src, span))
}

fn binding_source_site(
    provenance: &Provenance,
    store: &DigestStore,
    realm: ComponentId,
    target_key: &BindingTargetKey,
) -> Option<(NamedSource<Arc<str>>, SourceSpan)> {
    let (src, spans) = source_for_component(provenance, store, realm)?;
    let span = spans
        .bindings
        .get(target_key)
        .map(|b| b.capability.or(b.from).unwrap_or(b.whole))
        .unwrap_or((0usize, 0usize).into());
    Some((src, span))
}

fn binding_site(
    provenance: &Provenance,
    store: &DigestStore,
    realm: ComponentId,
    target_key: &BindingTargetKey,
) -> Option<(NamedSource<Arc<str>>, SourceSpan)> {
    let (src, spans) = source_for_component(provenance, store, realm)?;
    let span = spans
        .bindings
        .get(target_key)
        .map(|b| b.whole)
        .unwrap_or((0usize, 0usize).into());
    Some((src, span))
}

struct ConfigSite {
    src: NamedSource<Arc<str>>,
    span: SourceSpan,
    label: String,
}

fn config_site_for_component(
    components: &[Component],
    provenance: &Provenance,
    store: &DigestStore,
    id: ComponentId,
) -> Option<ConfigSite> {
    let component = &components[id.0];
    if let Some(parent) = component.parent {
        let (src, spans) = source_for_component(provenance, store, parent)?;
        let component_spans = spans.components.get(component.name.as_str())?;
        if component.config.is_some() {
            let span = component_spans.config.unwrap_or(component_spans.whole);
            return Some(ConfigSite {
                src,
                span,
                label: "config provided here".to_string(),
            });
        }
        return Some(ConfigSite {
            src,
            span: component_spans.name,
            label: "config required here".to_string(),
        });
    }

    let (src, spans) = source_for_component(provenance, store, id)?;
    Some(ConfigSite {
        src,
        span: spans.config_schema.unwrap_or((0usize, 0usize).into()),
        label: "config required for root component".to_string(),
    })
}

fn config_schema_site(
    provenance: &Provenance,
    store: &DigestStore,
    id: ComponentId,
    component_path: &str,
) -> Option<RelatedSpan> {
    let (src, spans) = source_for_component(provenance, store, id)?;
    let span = spans.config_schema.unwrap_or((0usize, 0usize).into());
    Some(RelatedSpan {
        message: format!("config schema for {component_path}"),
        src,
        span,
        label: "config schema declared here".to_string(),
    })
}

fn slots_section_site(
    provenance: &Provenance,
    store: &DigestStore,
    id: ComponentId,
    component_label: &str,
) -> Option<RelatedSpan> {
    let (src, spans) = source_for_component(provenance, store, id)?;
    let span = spans
        .slots_section
        .or_else(|| spans.slots.values().next().map(|s| s.whole))?;
    Some(RelatedSpan {
        message: format!("slots declared on {component_label}"),
        src,
        span,
        label: "slots declared here".to_string(),
    })
}

fn unknown_slot_help(component_label: &str, manifest: &Manifest) -> String {
    let mut names: Vec<_> = manifest
        .slots()
        .keys()
        .map(|name| name.to_string())
        .collect();
    if names.is_empty() {
        return format!(
            "No slots are declared on {component_label}. Declare slots in a `slots: {{ ... }}` \
             block, or fix the binding target."
        );
    }
    names.sort();
    format!(
        "Valid slots on {component_label}: {}",
        names.into_iter().take(20).collect::<Vec<_>>().join(", ")
    )
}

#[derive(Clone, Copy)]
struct BindingErrorSite<'a> {
    components: &'a [Component],
    provenance: &'a Provenance,
    store: &'a DigestStore,
    realm: ComponentId,
    target_key: &'a BindingTargetKey,
}

impl BindingErrorSite<'_> {
    fn unknown_slot(self, to_id: ComponentId, slot: &str, to_manifest: &Manifest) -> Error {
        let (src, span) =
            binding_target_site(self.provenance, self.store, self.realm, self.target_key)
                .unwrap_or_else(|| (unknown_source(), (0usize, 0usize).into()));
        let to_component_path = component_path_for(self.components, to_id);
        let to_component_label = describe_component_path(&to_component_path);
        let mut related: Vec<_> =
            component_decl_site(self.components, self.provenance, self.store, to_id)
                .into_iter()
                .collect();
        if let Some(site) =
            slots_section_site(self.provenance, self.store, to_id, &to_component_label)
        {
            related.push(site);
        }
        Error::UnknownSlot {
            to_component_path: to_component_label.clone(),
            slot: slot.to_string(),
            help: unknown_slot_help(&to_component_label, to_manifest),
            src,
            span,
            related,
        }
    }
}

fn unknown_provide_error(components: &[Component], component: ComponentId, provide: &str) -> Error {
    Error::UnknownProvide {
        component_path: describe_component_path(&component_path_for(components, component)),
        provide: provide.to_string(),
    }
}

fn not_exported_help(component_path: &str, manifest: &Manifest) -> String {
    let component_label = describe_component_path(component_path);
    let mut names: Vec<_> = manifest
        .exports()
        .keys()
        .map(|name| name.to_string())
        .collect();
    if names.is_empty() {
        return format!(
            "No exports are declared by {component_label}. Add an `exports: {{ ... }}` entry, or \
             fix the reference."
        );
    }
    names.sort();
    format!(
        "Valid exports on {component_label}: {}",
        names.into_iter().take(20).collect::<Vec<_>>().join(", ")
    )
}

#[allow(unused_assignments)]
#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum Error {
    #[error("linker reported {count} errors")]
    #[diagnostic(code(linker::multiple_errors))]
    Multiple {
        count: usize,
        #[related]
        errors: Vec<Error>,
    },

    #[error("missing manifest content for {component_path} (digest {digest})")]
    #[diagnostic(code(linker::missing_manifest))]
    MissingManifest {
        component_path: String,
        digest: ManifestDigest,
    },

    #[error("binding references unknown child `#{child}` in {component_path}")]
    #[diagnostic(code(linker::unknown_child))]
    UnknownChild {
        component_path: String,
        child: String,
    },

    #[error("unknown slot `{slot}` on {to_component_path}")]
    #[diagnostic(code(linker::unknown_slot), help("{help}"))]
    UnknownSlot {
        to_component_path: String,
        slot: String,
        help: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label(primary, "binding references this slot")]
        span: SourceSpan,
        #[related]
        related: Vec<RelatedSpan>,
    },

    #[error("unknown provide `{provide}` on {component_path}")]
    #[diagnostic(code(linker::unknown_provide))]
    UnknownProvide {
        component_path: String,
        provide: String,
    },

    #[error("`{name}` is not exported by {component_path}")]
    #[diagnostic(code(linker::not_exported), help("{help}"))]
    NotExported {
        component_path: String,
        name: String,
        help: String,
        #[source_code]
        src: Option<NamedSource<Arc<str>>>,
        #[label(primary, "missing export `{name}`")]
        span: Option<SourceSpan>,
    },

    #[error("invalid export `{name}` on {component_path}: {message}")]
    #[diagnostic(code(linker::invalid_export), help("{help}"))]
    InvalidExport {
        component_path: String,
        name: String,
        message: String,
        help: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label(primary, "export declared here")]
        span: SourceSpan,
    },

    #[error("type mismatch for slot `{to_component_path}.{slot}`: expected {expected}, got {got}")]
    #[diagnostic(
        code(linker::type_mismatch),
        help(
            "Bind a provide of type `{expected}` to `{to_component_path}.{slot}`, or change the \
             slot/provide `kind`/`profile` so they match."
        )
    )]
    TypeMismatch {
        to_component_path: String,
        slot: String,
        expected: CapabilityDecl,
        got: CapabilityDecl,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label(primary, "binding provides `{got}` to slot expecting `{expected}`")]
        span: SourceSpan,
        #[related]
        related: Vec<RelatedSpan>,
    },

    #[error("slot `{slot}` on {component_path} is not bound (non-optional slots must be filled)")]
    #[diagnostic(code(linker::unbound_slot))]
    UnboundSlot {
        component_path: String,
        slot: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label(primary, "slot declared here")]
        span: SourceSpan,
        #[related]
        related: Vec<RelatedSpan>,
    },

    #[error(
        "slot `{slot}` on {to_component_path} is bound more than once (from {first_from} and \
         {second_from})"
    )]
    #[diagnostic(code(linker::duplicate_slot_binding))]
    DuplicateSlotBinding {
        to_component_path: String,
        slot: String,
        first_from: String,
        second_from: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label(primary, "second binding here")]
        span: SourceSpan,
        #[related]
        related: Vec<RelatedSpan>,
    },

    #[error("invalid config for {component_path}: {message}")]
    #[diagnostic(code(linker::invalid_config))]
    InvalidConfig {
        component_path: String,
        message: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label(primary, "{label}")]
        span: SourceSpan,
        label: String,
        #[related]
        related: Vec<RelatedSpan>,
    },

    #[error("unsupported manifest feature `{feature}` in {component_path}")]
    #[diagnostic(code(linker::unsupported_feature))]
    UnsupportedManifestFeature {
        component_path: String,
        feature: &'static str,
    },
}

pub(crate) struct ResolvedExport {
    pub(crate) component: ComponentId,
    pub(crate) name: String,
    pub(crate) decl: CapabilityDecl,
}

pub fn link(tree: ResolvedTree, store: &DigestStore) -> Result<(Scenario, Provenance), Error> {
    let mut components = Vec::new();
    let mut provenance = Provenance::default();
    let root = flatten(&tree.root, None, "/", &mut components, &mut provenance);

    debug_assert_eq!(components.len(), provenance.components.len());

    let manifests =
        crate::manifest_table::build_manifest_table(&components, store).map_err(|e| {
            Error::MissingManifest {
                component_path: component_path_for(&components, e.component),
                digest: e.digest,
            }
        })?;

    for (c, m) in components.iter_mut().zip(&manifests) {
        c.has_program = m.program().is_some();
    }

    let mut schema_cache: HashMap<ManifestDigest, Arc<Validator>> = HashMap::new();
    let mut errors = Vec::new();

    for id in (0..components.len()).map(ComponentId) {
        if let Err(err) = validate_config(
            id,
            &components,
            &manifests,
            &provenance,
            store,
            &mut schema_cache,
        ) {
            errors.push(err);
        }
        validate_exports(id, &components, &manifests, &provenance, store, &mut errors);
    }

    let (bindings, origins) =
        resolve_bindings(&components, &manifests, &provenance, store, &mut errors);
    validate_unique_slot_bindings(
        &components,
        &bindings,
        &origins,
        &provenance,
        store,
        &mut errors,
    );
    validate_all_slots_bound(
        &components,
        &manifests,
        &bindings,
        &provenance,
        store,
        &mut errors,
    );

    if !errors.is_empty() {
        return Err(Error::Multiple {
            count: errors.len(),
            errors,
        });
    }

    let root_manifest = &manifests[root.0];
    provenance.root_exports = root_manifest
        .exports()
        .keys()
        .map(|export_name| {
            let resolved = resolve_export(&components, &manifests, root, export_name)
                .expect("export was validated during linking");
            RootExportProvenance {
                name: Arc::from(export_name.to_string()),
                endpoint_component_path: Arc::clone(
                    &provenance.for_component(resolved.component).authored_path,
                ),
                endpoint_provide: Arc::from(resolved.name),
                kind: resolved.decl.kind,
            }
        })
        .collect();

    Ok((
        Scenario {
            root,
            components,
            bindings,
        },
        provenance,
    ))
}

fn flatten(
    node: &ResolvedNode,
    parent: Option<ComponentId>,
    parent_path: &str,
    out: &mut Vec<Component>,
    prov: &mut Provenance,
) -> ComponentId {
    let id = ComponentId(out.len());

    let authored_path: Arc<str> = if parent.is_none() {
        Arc::from("/")
    } else if parent_path == "/" {
        Arc::from(format!("/{}", node.name))
    } else {
        Arc::from(format!("{parent_path}/{}", node.name))
    };

    out.push(Component {
        id,
        parent,
        name: node.name.clone(),
        has_program: false,
        digest: node.digest,
        config: node.config.clone(),
        children: BTreeMap::new(),
    });

    prov.components.push(ComponentProvenance {
        authored_path: Arc::clone(&authored_path),
        declared_ref: node.declared_ref.clone(),
        resolved_url: node.resolved_url.clone(),
        digest: node.digest,
        observed_url: node.observed_url.clone(),
    });

    let mut children = BTreeMap::new();
    for (child_name, child_node) in node.children.iter() {
        let child_id = flatten(child_node, Some(id), authored_path.as_ref(), out, prov);
        children.insert(child_name.clone(), child_id);
    }

    out[id.0].children = children;
    id
}

fn validate_config(
    id: ComponentId,
    components: &[Component],
    manifests: &[Arc<Manifest>],
    provenance: &Provenance,
    store: &DigestStore,
    schema_cache: &mut HashMap<ManifestDigest, Arc<Validator>>,
) -> Result<(), Error> {
    let c = &components[id.0];
    let m = &manifests[id.0];

    let Some(schema_decl) = m.config_schema() else {
        return Ok(());
    };

    let validator = if let Some(v) = schema_cache.get(&c.digest) {
        Arc::clone(v)
    } else {
        let v =
            Arc::new(jsonschema::validator_for(&schema_decl.0).map_err(|e| {
                let component_path = component_path_for(components, id);
                let site = config_site_for_component(components, provenance, store, id)
                    .unwrap_or_else(|| ConfigSite {
                        src: unknown_source(),
                        span: (0usize, 0usize).into(),
                        label: "config here".to_string(),
                    });
                let mut related = Vec::new();
                if c.parent.is_some()
                    && let Some(schema) = config_schema_site(provenance, store, id, &component_path)
                {
                    related.push(schema);
                }
                Error::InvalidConfig {
                    component_path,
                    message: e.to_string(),
                    src: site.src,
                    span: site.span,
                    label: site.label,
                    related,
                }
            })?);
        schema_cache.insert(c.digest, Arc::clone(&v));
        v
    };

    let empty = Value::Object(Map::new());
    let effective = c.config.as_ref().unwrap_or(&empty);

    let mut errors = validator.iter_errors(effective);
    let Some(first) = errors.next() else {
        return Ok(());
    };

    let instance_path = first.instance_path().to_string();
    let mut msgs = vec![first.to_string()];
    msgs.extend(errors.take(7).map(|e| e.to_string()));
    let component_path = component_path_for(components, id);
    let mut site =
        config_site_for_component(components, provenance, store, id).unwrap_or_else(|| {
            ConfigSite {
                src: unknown_source(),
                span: (0usize, 0usize).into(),
                label: "config here".to_string(),
            }
        });
    if let Some(parent) = c.parent
        && c.config.is_some()
        && let Some(stored) = store.get_source(provenance.for_component(parent).effective_url())
        && let Some(component_spans) = stored.spans.components.get(c.name.as_str())
        && let Some(config_span) = component_spans.config
        && let Some(span) = amber_manifest::span_for_json_pointer(
            stored.source.as_ref(),
            config_span,
            &instance_path,
        )
    {
        let url = provenance.for_component(parent).effective_url();
        let name = crate::store::display_url(url);
        site.src = NamedSource::new(name, Arc::clone(&stored.source)).with_language("json5");
        site.span = span;
        site.label = "invalid config value here".to_string();
    }
    let mut related = Vec::new();
    if c.parent.is_some()
        && let Some(schema) = config_schema_site(provenance, store, id, &component_path)
    {
        related.push(schema);
    }
    let message = if c.parent.is_none() && c.config.is_none() {
        format!(
            "{} (no config provided for root component)",
            msgs.join("; ")
        )
    } else {
        msgs.join("; ")
    };
    Err(Error::InvalidConfig {
        component_path,
        message,
        src: site.src,
        span: site.span,
        label: site.label,
        related,
    })
}

fn validate_exports(
    realm: ComponentId,
    components: &[Component],
    manifests: &[Arc<Manifest>],
    provenance: &Provenance,
    store: &DigestStore,
    errors: &mut Vec<Error>,
) {
    let realm_manifest = &manifests[realm.0];
    let realm_path = component_path_for(components, realm);
    let realm_label = describe_component_path(&realm_path);

    for (export_name, target) in realm_manifest.exports().iter() {
        let ExportTarget::ChildExport { child, export } = target else {
            continue;
        };

        let child_id = match child_component_id(components, realm, child) {
            Ok(id) => id,
            Err(err) => {
                errors.push(err);
                continue;
            }
        };
        if let Err(err) = resolve_export(components, manifests, child_id, export) {
            let (message, help) = match err {
                Error::NotExported {
                    component_path,
                    name,
                    help,
                    ..
                } => (
                    format!(
                        "target references non-exported `{name}` on {}",
                        describe_component_path(&component_path)
                    ),
                    help,
                ),
                other => (
                    other.to_string(),
                    "Ensure the export target points to an existing export/provide.".to_string(),
                ),
            };

            let (src, span) = source_for_component(provenance, store, realm).map_or_else(
                || (unknown_source(), (0usize, 0usize).into()),
                |(src, spans)| {
                    let span = spans
                        .exports
                        .get(export_name.as_str())
                        .map(|e| e.target)
                        .unwrap_or((0usize, 0usize).into());
                    (src, span)
                },
            );
            errors.push(Error::InvalidExport {
                component_path: realm_label.clone(),
                name: export_name.to_string(),
                message,
                help,
                src,
                span,
            });
        }
    }
}

#[derive(Clone, Debug)]
struct BindingOrigin {
    realm: ComponentId,
    target_key: BindingTargetKey,
}

struct ResolvedBindingTarget {
    slot_ref: SlotRef,
    slot_decl: CapabilityDecl,
}

struct ResolvedBindingSource {
    provide_ref: ProvideRef,
    provide_decl: CapabilityDecl,
}

fn push_error<T>(errors: &mut Vec<Error>, res: Result<T, Error>) -> Option<T> {
    match res {
        Ok(value) => Some(value),
        Err(err) => {
            errors.push(err);
            None
        }
    }
}

fn resolve_binding_target(
    components: &[Component],
    manifests: &[Arc<Manifest>],
    site: BindingErrorSite<'_>,
    target: &BindingTarget,
) -> Result<ResolvedBindingTarget, Error> {
    match target {
        BindingTarget::SelfSlot(slot_name) => {
            let to_id = site.realm;
            let to_manifest = &manifests[to_id.0];
            let slot_decl = to_manifest.slots().get(slot_name).ok_or_else(|| {
                site.unknown_slot(to_id, slot_name.as_str(), to_manifest.as_ref())
            })?;
            let slot_name = slot_name.to_string();
            Ok(ResolvedBindingTarget {
                slot_ref: SlotRef {
                    component: to_id,
                    name: slot_name.clone(),
                },
                slot_decl: slot_decl.decl.clone(),
            })
        }
        BindingTarget::ChildSlot { child, slot } => {
            let to_id = child_component_id(components, site.realm, child)?;
            let to_manifest = &manifests[to_id.0];
            let slot_decl = to_manifest
                .slots()
                .get(slot.as_str())
                .ok_or_else(|| site.unknown_slot(to_id, slot.as_str(), to_manifest.as_ref()))?;
            let slot_name = slot.to_string();
            Ok(ResolvedBindingTarget {
                slot_ref: SlotRef {
                    component: to_id,
                    name: slot_name.clone(),
                },
                slot_decl: slot_decl.decl.clone(),
            })
        }
        _ => Err(Error::UnsupportedManifestFeature {
            component_path: component_path_for(components, site.realm),
            feature: "binding target",
        }),
    }
}

fn resolve_binding_source(
    components: &[Component],
    manifests: &[Arc<Manifest>],
    provenance: &Provenance,
    store: &DigestStore,
    realm: ComponentId,
    target_key: &BindingTargetKey,
    source: &BindingSource,
) -> Result<ResolvedBindingSource, Error> {
    match source {
        BindingSource::SelfProvide(provide_name) => {
            let from_id = realm;
            let from_manifest = &manifests[from_id.0];
            let provide_decl = from_manifest
                .provides()
                .get(provide_name)
                .ok_or_else(|| unknown_provide_error(components, from_id, provide_name.as_str()))?;
            Ok(ResolvedBindingSource {
                provide_ref: ProvideRef {
                    component: from_id,
                    name: provide_name.to_string(),
                },
                provide_decl: provide_decl.decl.clone(),
            })
        }
        BindingSource::ChildExport { child, export } => {
            let from_id = child_component_id(components, realm, child)?;
            let resolved = resolve_export(components, manifests, from_id, export).map_err(
                |err| match err {
                    Error::NotExported {
                        component_path,
                        name,
                        help,
                        ..
                    } => {
                        let (src, span) = binding_source_site(provenance, store, realm, target_key)
                            .unwrap_or_else(|| (unknown_source(), (0usize, 0usize).into()));
                        Error::NotExported {
                            component_path,
                            name,
                            help,
                            src: Some(src),
                            span: Some(span),
                        }
                    }
                    other => other,
                },
            )?;
            Ok(ResolvedBindingSource {
                provide_ref: ProvideRef {
                    component: resolved.component,
                    name: resolved.name,
                },
                provide_decl: resolved.decl,
            })
        }
        _ => Err(Error::UnsupportedManifestFeature {
            component_path: component_path_for(components, realm),
            feature: "binding source",
        }),
    }
}

fn type_mismatch_error(
    components: &[Component],
    provenance: &Provenance,
    store: &DigestStore,
    realm: ComponentId,
    target_key: &BindingTargetKey,
    target: ResolvedBindingTarget,
    source: ResolvedBindingSource,
) -> Error {
    let ResolvedBindingTarget {
        slot_ref,
        slot_decl,
    } = target;
    let ResolvedBindingSource {
        provide_ref,
        provide_decl,
    } = source;
    let (src, span) = binding_site(provenance, store, realm, target_key)
        .unwrap_or_else(|| (unknown_source(), (0usize, 0usize).into()));

    let mut related = Vec::new();

    let to_id = slot_ref.component;
    let slot_name = slot_ref.name.as_str();
    if let Some((slot_src, slot_spans)) = source_for_component(provenance, store, to_id)
        && let Some(slot_decl_spans) = slot_spans.slots.get(slot_name)
    {
        let span = slot_decl_spans.kind.unwrap_or(slot_decl_spans.whole);
        related.push(RelatedSpan {
            message: format!(
                "slot `{}` declared on {}",
                slot_name,
                component_path_for(components, to_id)
            ),
            src: slot_src,
            span,
            label: "slot type declared here".to_string(),
        });
    }

    if let Some((provide_src, provide_spans)) =
        source_for_component(provenance, store, provide_ref.component)
    {
        let provide_name = provide_ref.name.as_str();
        if let Some(p) = provide_spans.provides.get(provide_name) {
            let span = p.capability.kind.unwrap_or(p.capability.whole);
            related.push(RelatedSpan {
                message: format!(
                    "provide `{provide_name}` declared on {}",
                    component_path_for(components, provide_ref.component)
                ),
                src: provide_src,
                span,
                label: "provide type declared here".to_string(),
            });
        }
    }

    Error::TypeMismatch {
        to_component_path: component_path_for(components, to_id),
        slot: slot_ref.name,
        expected: slot_decl,
        got: provide_decl,
        src,
        span,
        related,
    }
}

fn resolve_bindings(
    components: &[Component],
    manifests: &[Arc<Manifest>],
    provenance: &Provenance,
    store: &DigestStore,
    errors: &mut Vec<Error>,
) -> (Vec<BindingEdge>, Vec<BindingOrigin>) {
    let mut edges = Vec::new();
    let mut origins = Vec::new();

    for realm in (0..components.len()).map(ComponentId) {
        let realm_manifest = &manifests[realm.0];

        for (target, binding) in realm_manifest.bindings().iter() {
            let target_key = BindingTargetKey::from(target);
            let site = BindingErrorSite {
                components,
                provenance,
                store,
                realm,
                target_key: &target_key,
            };
            let target = match push_error(
                errors,
                resolve_binding_target(components, manifests, site, target),
            ) {
                Some(target) => target,
                None => continue,
            };
            let source = match push_error(
                errors,
                resolve_binding_source(
                    components,
                    manifests,
                    provenance,
                    store,
                    realm,
                    &target_key,
                    &binding.from,
                ),
            ) {
                Some(source) => source,
                None => continue,
            };

            if target.slot_decl != source.provide_decl {
                errors.push(type_mismatch_error(
                    components,
                    provenance,
                    store,
                    realm,
                    &target_key,
                    target,
                    source,
                ));
                continue;
            }

            edges.push(BindingEdge {
                from: source.provide_ref,
                to: target.slot_ref,
                weak: binding.weak,
            });
            origins.push(BindingOrigin { realm, target_key });
        }
    }

    (edges, origins)
}

fn child_component_id(
    components: &[Component],
    realm: ComponentId,
    child: &ChildName,
) -> Result<ComponentId, Error> {
    components[realm.0]
        .children
        .get(child.as_str())
        .copied()
        .ok_or_else(|| Error::UnknownChild {
            component_path: component_path_for(components, realm),
            child: child.to_string(),
        })
}

pub(crate) fn resolve_export(
    components: &[Component],
    manifests: &[Arc<Manifest>],
    component: ComponentId,
    export_name: &ExportName,
) -> Result<ResolvedExport, Error> {
    let manifest = &manifests[component.0];
    let Some(target) = manifest.exports().get(export_name) else {
        let component_path = component_path_for(components, component);
        return Err(Error::NotExported {
            help: not_exported_help(&component_path, manifest),
            component_path,
            name: export_name.to_string(),
            src: None,
            span: None,
        });
    };

    match target {
        ExportTarget::SelfProvide(provide_name) => {
            let provide_decl = manifest.provides().get(provide_name).ok_or_else(|| {
                unknown_provide_error(components, component, provide_name.as_str())
            })?;
            Ok(ResolvedExport {
                component,
                name: provide_name.to_string(),
                decl: provide_decl.decl.clone(),
            })
        }
        ExportTarget::ChildExport { child, export } => {
            let child_id = child_component_id(components, component, child)?;
            resolve_export(components, manifests, child_id, export)
        }
        _ => Err(Error::UnsupportedManifestFeature {
            component_path: component_path_for(components, component),
            feature: "export target",
        }),
    }
}

fn validate_all_slots_bound(
    components: &[Component],
    manifests: &[Arc<Manifest>],
    bindings: &[BindingEdge],
    provenance: &Provenance,
    store: &DigestStore,
    errors: &mut Vec<Error>,
) {
    let mut satisfied: HashSet<(ComponentId, &str)> = HashSet::new();
    for b in bindings {
        satisfied.insert((b.to.component, b.to.name.as_str()));
    }

    for id in (0..components.len()).map(ComponentId) {
        let m = &manifests[id.0];
        for slot_name in m.slots().keys() {
            if satisfied.contains(&(id, slot_name.as_str())) {
                continue;
            }
            let (src, span) = source_for_component(provenance, store, id).map_or_else(
                || (unknown_source(), (0usize, 0usize).into()),
                |(src, spans)| {
                    let span = spans
                        .slots
                        .get(slot_name.as_str())
                        .map(|s| s.name)
                        .unwrap_or((0usize, 0usize).into());
                    (src, span)
                },
            );
            let related = component_decl_site(components, provenance, store, id)
                .into_iter()
                .collect();
            errors.push(Error::UnboundSlot {
                component_path: describe_component_path(&component_path_for(components, id)),
                slot: slot_name.to_string(),
                src,
                span,
                related,
            });
        }
    }
}

fn validate_unique_slot_bindings(
    components: &[Component],
    bindings: &[BindingEdge],
    origins: &[BindingOrigin],
    provenance: &Provenance,
    store: &DigestStore,
    errors: &mut Vec<Error>,
) {
    let mut seen: HashMap<(ComponentId, String), (ProvideRef, usize)> = HashMap::new();

    for (idx, b) in bindings.iter().enumerate() {
        let key = (b.to.component, b.to.name.clone());
        if let Some((prev_from, prev_idx)) = seen.insert(key, (b.from.clone(), idx)) {
            let to_component_path = component_path_for(components, b.to.component);

            let first_from = format!(
                "{}.{}",
                component_path_for(components, prev_from.component),
                prev_from.name
            );
            let second_from = format!(
                "{}.{}",
                component_path_for(components, b.from.component),
                b.from.name
            );

            let second_origin = origins.get(idx);
            let first_origin = origins.get(prev_idx);

            let (src, span) = second_origin
                .and_then(|o| binding_site(provenance, store, o.realm, &o.target_key))
                .unwrap_or_else(|| (unknown_source(), (0usize, 0usize).into()));

            let mut related = Vec::new();
            if let Some(first_origin) = first_origin
                && let Some((first_src, first_span)) = binding_site(
                    provenance,
                    store,
                    first_origin.realm,
                    &first_origin.target_key,
                )
            {
                related.push(RelatedSpan {
                    message: "first binding".to_string(),
                    src: first_src,
                    span: first_span,
                    label: "first binding here".to_string(),
                });
            }

            errors.push(Error::DuplicateSlotBinding {
                to_component_path,
                slot: b.to.name.clone(),
                first_from,
                second_from,
                src,
                span,
                related,
            });
        }
    }
}
