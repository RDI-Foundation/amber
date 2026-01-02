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

#[derive(Clone, Debug, Default)]
struct LinkIndex {
    child_by_name: BTreeMap<ChildName, ComponentId>,
}

impl LinkIndex {
    fn child_id(&self, child: &ChildName) -> ComponentId {
        *self.child_by_name.get(child).expect("child should exist")
    }
}

fn component(components: &[Option<Component>], id: ComponentId) -> &Component {
    components[id.0].as_ref().expect("component should exist")
}

fn component_local_name(component: &Component) -> &str {
    component
        .moniker
        .local_name()
        .expect("component should have a local name")
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
    components: &[Option<Component>],
    provenance: &Provenance,
    store: &DigestStore,
    id: ComponentId,
) -> Option<RelatedSpan> {
    let component = component(components, id);
    let parent = component.parent?;
    let (src, spans) = source_for_component(provenance, store, parent)?;
    let name = component_local_name(component);
    let span = spans.components.get(name)?.name;
    let parent_path = describe_component_path(&component_path_for(components, parent));
    Some(RelatedSpan {
        message: format!("component `{}` declared on {}", name, parent_path),
        src,
        span,
        label: "component declared here".to_string(),
    })
}

fn binding_site_with(
    provenance: &Provenance,
    store: &DigestStore,
    realm: ComponentId,
    target_key: &BindingTargetKey,
    select: impl FnOnce(&amber_manifest::BindingSpans) -> SourceSpan,
) -> Option<(NamedSource<Arc<str>>, SourceSpan)> {
    let (src, spans) = source_for_component(provenance, store, realm)?;
    let span = spans
        .bindings
        .get(target_key)
        .map(select)
        .unwrap_or((0usize, 0usize).into());
    Some((src, span))
}

fn binding_target_site(
    provenance: &Provenance,
    store: &DigestStore,
    realm: ComponentId,
    target_key: &BindingTargetKey,
) -> Option<(NamedSource<Arc<str>>, SourceSpan)> {
    binding_site_with(provenance, store, realm, target_key, |b| {
        b.slot.or(b.to).unwrap_or(b.whole)
    })
}

fn binding_source_site(
    provenance: &Provenance,
    store: &DigestStore,
    realm: ComponentId,
    target_key: &BindingTargetKey,
) -> Option<(NamedSource<Arc<str>>, SourceSpan)> {
    binding_site_with(provenance, store, realm, target_key, |b| {
        b.capability.or(b.from).unwrap_or(b.whole)
    })
}

fn binding_site(
    provenance: &Provenance,
    store: &DigestStore,
    realm: ComponentId,
    target_key: &BindingTargetKey,
) -> Option<(NamedSource<Arc<str>>, SourceSpan)> {
    binding_site_with(provenance, store, realm, target_key, |b| b.whole)
}

struct ConfigSite {
    src: NamedSource<Arc<str>>,
    span: SourceSpan,
    label: String,
}

struct ConfigErrorSite<'a> {
    components: &'a [Option<Component>],
    provenance: &'a Provenance,
    store: &'a DigestStore,
    id: ComponentId,
}

impl<'a> ConfigErrorSite<'a> {
    fn new(
        components: &'a [Option<Component>],
        provenance: &'a Provenance,
        store: &'a DigestStore,
        id: ComponentId,
    ) -> Self {
        Self {
            components,
            provenance,
            store,
            id,
        }
    }

    fn component(&self) -> &Component {
        component(self.components, self.id)
    }

    fn config_site(&self) -> ConfigSite {
        config_site_for_component(self.components, self.provenance, self.store, self.id)
            .unwrap_or_else(|| ConfigSite {
                src: unknown_source(),
                span: (0usize, 0usize).into(),
                label: "config here".to_string(),
            })
    }

    fn invalid_value_site(&self, instance_path: &str) -> Option<ConfigSite> {
        let component = self.component();
        let parent = component.parent?;
        component.config.as_ref()?;
        let parent_prov = self.provenance.for_component(parent);
        let stored = self.store.get_source(parent_prov.effective_url())?;
        let component_spans = stored
            .spans
            .components
            .get(component_local_name(component))?;
        let config_span = component_spans.config?;
        let span = amber_manifest::span_for_json_pointer(
            stored.source.as_ref(),
            config_span,
            instance_path,
        )?;
        let name = crate::store::display_url(parent_prov.effective_url());
        Some(ConfigSite {
            src: NamedSource::new(name, Arc::clone(&stored.source)).with_language("json5"),
            span,
            label: "invalid config value here".to_string(),
        })
    }

    fn schema_related_site(&self, component_path: &str) -> Option<RelatedSpan> {
        if self.component().parent.is_some() {
            config_schema_site(self.provenance, self.store, self.id, component_path)
        } else {
            None
        }
    }
}

fn config_site_for_component(
    components: &[Option<Component>],
    provenance: &Provenance,
    store: &DigestStore,
    id: ComponentId,
) -> Option<ConfigSite> {
    let component = component(components, id);
    if let Some(parent) = component.parent {
        let (src, spans) = source_for_component(provenance, store, parent)?;
        let component_spans = spans.components.get(component_local_name(component))?;
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
    components: &'a [Option<Component>],
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
    let mut link_index = Vec::new();
    let mut provenance = Provenance::default();
    let root = flatten(
        &tree.root,
        None,
        "/",
        &mut components,
        &mut provenance,
        &mut link_index,
    );

    debug_assert_eq!(components.len(), provenance.components.len());
    debug_assert_eq!(components.len(), link_index.len());

    let manifests =
        crate::manifest_table::build_manifest_table(&components, store).map_err(|e| {
            Error::MissingManifest {
                component_path: component_path_for(&components, e.component),
                digest: e.digest,
            }
        })?;

    for (c, m) in components.iter_mut().zip(&manifests) {
        let (Some(c), Some(m)) = (c.as_mut(), m.as_ref()) else {
            continue;
        };
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
        validate_exports(
            id,
            &components,
            &manifests,
            &link_index,
            &provenance,
            store,
            &mut errors,
        );
    }

    let (bindings, origins) = resolve_bindings(
        &components,
        &manifests,
        &link_index,
        &provenance,
        store,
        &mut errors,
    );
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

    let root_manifest = manifests[root.0]
        .as_ref()
        .expect("root manifest should exist");
    provenance.root_exports = root_manifest
        .exports()
        .keys()
        .map(|export_name| {
            let resolved = resolve_export(&components, &manifests, &link_index, root, export_name)
                .expect("export was validated during linking");
            RootExportProvenance {
                name: Arc::from(export_name.to_string()),
                endpoint_component_moniker: provenance
                    .for_component(resolved.component)
                    .authored_moniker
                    .clone(),
                endpoint_provide: Arc::from(resolved.name),
                kind: resolved.decl.kind,
            }
        })
        .collect();

    let mut scenario = Scenario {
        root,
        components,
        bindings,
    };
    scenario.normalize_child_order_by_moniker();
    scenario.assert_invariants();

    Ok((scenario, provenance))
}

fn flatten(
    node: &ResolvedNode,
    parent: Option<ComponentId>,
    parent_path: &str,
    out: &mut Vec<Option<Component>>,
    prov: &mut Provenance,
    link_index: &mut Vec<LinkIndex>,
) -> ComponentId {
    let id = ComponentId(out.len());

    let authored_moniker: Arc<str> = if parent.is_none() {
        Arc::from("/")
    } else if parent_path == "/" {
        Arc::from(format!("/{}", node.name))
    } else {
        Arc::from(format!("{parent_path}/{}", node.name))
    };

    let moniker = Arc::clone(&authored_moniker).into();

    out.push(Some(Component {
        id,
        parent,
        moniker,
        has_program: false,
        digest: node.digest,
        config: node.config.clone(),
        children: Vec::new(),
    }));
    link_index.push(LinkIndex::default());

    prov.components.push(ComponentProvenance {
        authored_moniker: Arc::clone(&authored_moniker).into(),
        declared_ref: node.declared_ref.clone(),
        resolved_url: node.resolved_url.clone(),
        digest: node.digest,
        observed_url: node.observed_url.clone(),
    });

    let mut children = Vec::with_capacity(node.children.len());
    let mut child_by_name = BTreeMap::new();
    for (child_name, child_node) in node.children.iter() {
        let child_id = flatten(
            child_node,
            Some(id),
            authored_moniker.as_ref(),
            out,
            prov,
            link_index,
        );
        children.push(child_id);
        let child_name =
            ChildName::try_from(child_name.as_str()).expect("child name should be validated");
        child_by_name.insert(child_name, child_id);
    }

    out[id.0].as_mut().expect("component should exist").children = children;
    link_index[id.0].child_by_name = child_by_name;
    id
}

fn validate_config(
    id: ComponentId,
    components: &[Option<Component>],
    manifests: &[Option<Arc<Manifest>>],
    provenance: &Provenance,
    store: &DigestStore,
    schema_cache: &mut HashMap<ManifestDigest, Arc<Validator>>,
) -> Result<(), Error> {
    let c = component(components, id);
    let m = manifests[id.0].as_ref().expect("manifest should exist");

    let Some(schema_decl) = m.config_schema() else {
        return Ok(());
    };

    let error_site = ConfigErrorSite::new(components, provenance, store, id);

    let validator = if let Some(v) = schema_cache.get(&c.digest) {
        Arc::clone(v)
    } else {
        let component_path = component_path_for(components, id);
        let site = error_site.config_site();
        let mut related = Vec::new();
        if let Some(schema) = error_site.schema_related_site(&component_path) {
            related.push(schema);
        }
        let v = Arc::new(jsonschema::validator_for(&schema_decl.0).map_err(|e| {
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
    let mut site = error_site.config_site();
    if let Some(value_site) = error_site.invalid_value_site(&instance_path) {
        site = value_site;
    }
    let mut related = Vec::new();
    if let Some(schema) = error_site.schema_related_site(&component_path) {
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
    components: &[Option<Component>],
    manifests: &[Option<Arc<Manifest>>],
    link_index: &[LinkIndex],
    provenance: &Provenance,
    store: &DigestStore,
    errors: &mut Vec<Error>,
) {
    let realm_manifest = manifests[realm.0].as_ref().expect("manifest should exist");
    let realm_path = component_path_for(components, realm);
    let realm_label = describe_component_path(&realm_path);

    for (export_name, target) in realm_manifest.exports().iter() {
        let ExportTarget::ChildExport { child, export } = target else {
            continue;
        };

        let child_id = child_component_id(link_index, realm, child);
        if let Err(err) = resolve_export(components, manifests, link_index, child_id, export) {
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
    manifests: &[Option<Arc<Manifest>>],
    link_index: &[LinkIndex],
    site: BindingErrorSite<'_>,
    target: &BindingTarget,
) -> Result<ResolvedBindingTarget, Error> {
    match target {
        BindingTarget::SelfSlot(slot_name) => {
            let to_id = site.realm;
            let to_manifest = manifests[to_id.0].as_ref().expect("manifest should exist");
            let slot_decl = to_manifest
                .slots()
                .get(slot_name)
                .expect("manifest invariant: self slot exists");
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
            let to_id = child_component_id(link_index, site.realm, child);
            let to_manifest = manifests[to_id.0].as_ref().expect("manifest should exist");
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
            component_path: component_path_for(site.components, site.realm),
            feature: "binding target",
        }),
    }
}

fn resolve_binding_source(
    manifests: &[Option<Arc<Manifest>>],
    link_index: &[LinkIndex],
    site: BindingErrorSite<'_>,
    source: &BindingSource,
) -> Result<ResolvedBindingSource, Error> {
    match source {
        BindingSource::SelfProvide(provide_name) => {
            let from_id = site.realm;
            let from_manifest = manifests[from_id.0]
                .as_ref()
                .expect("manifest should exist");
            let provide_decl = from_manifest
                .provides()
                .get(provide_name)
                .expect("manifest invariant: self provide exists");
            Ok(ResolvedBindingSource {
                provide_ref: ProvideRef {
                    component: from_id,
                    name: provide_name.to_string(),
                },
                provide_decl: provide_decl.decl.clone(),
            })
        }
        BindingSource::ChildExport { child, export } => {
            let from_id = child_component_id(link_index, site.realm, child);
            let resolved = resolve_export(site.components, manifests, link_index, from_id, export)
                .map_err(|err| match err {
                    Error::NotExported {
                        component_path,
                        name,
                        help,
                        ..
                    } => {
                        let (src, span) = binding_source_site(
                            site.provenance,
                            site.store,
                            site.realm,
                            site.target_key,
                        )
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
                })?;
            Ok(ResolvedBindingSource {
                provide_ref: ProvideRef {
                    component: resolved.component,
                    name: resolved.name,
                },
                provide_decl: resolved.decl,
            })
        }
        _ => Err(Error::UnsupportedManifestFeature {
            component_path: component_path_for(site.components, site.realm),
            feature: "binding source",
        }),
    }
}

fn type_mismatch_error(
    components: &[Option<Component>],
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
    components: &[Option<Component>],
    manifests: &[Option<Arc<Manifest>>],
    link_index: &[LinkIndex],
    provenance: &Provenance,
    store: &DigestStore,
    errors: &mut Vec<Error>,
) -> (Vec<BindingEdge>, Vec<BindingOrigin>) {
    let mut edges = Vec::new();
    let mut origins = Vec::new();

    for realm in (0..components.len()).map(ComponentId) {
        let realm_manifest = manifests[realm.0].as_ref().expect("manifest should exist");

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
                resolve_binding_target(manifests, link_index, site, target),
            ) {
                Some(target) => target,
                None => continue,
            };
            let source = match push_error(
                errors,
                resolve_binding_source(manifests, link_index, site, &binding.from),
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
    link_index: &[LinkIndex],
    realm: ComponentId,
    child: &ChildName,
) -> ComponentId {
    link_index[realm.0].child_id(child)
}

fn resolve_export(
    components: &[Option<Component>],
    manifests: &[Option<Arc<Manifest>>],
    link_index: &[LinkIndex],
    component: ComponentId,
    export_name: &ExportName,
) -> Result<ResolvedExport, Error> {
    let manifest = manifests[component.0]
        .as_ref()
        .expect("manifest should exist");
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
            let provide_decl = manifest
                .provides()
                .get(provide_name)
                .expect("manifest invariant: self provide exists");
            Ok(ResolvedExport {
                component,
                name: provide_name.to_string(),
                decl: provide_decl.decl.clone(),
            })
        }
        ExportTarget::ChildExport { child, export } => {
            let child_id = child_component_id(link_index, component, child);
            resolve_export(components, manifests, link_index, child_id, export)
        }
        _ => Err(Error::UnsupportedManifestFeature {
            component_path: component_path_for(components, component),
            feature: "export target",
        }),
    }
}

fn validate_all_slots_bound(
    components: &[Option<Component>],
    manifests: &[Option<Arc<Manifest>>],
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
        let m = manifests[id.0].as_ref().expect("manifest should exist");
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
    components: &[Option<Component>],
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
