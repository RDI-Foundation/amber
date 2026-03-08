#![allow(unused_assignments)]
#![allow(clippy::result_large_err)]

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

use amber_config as rc;
use amber_manifest::{
    BindingSource, BindingTarget, BindingTargetKey, CapabilityDecl, CapabilityKind, ChildName,
    ExportName, ExportTarget, InterpolatedPart, InterpolatedString, InterpolationSource, Manifest,
    ManifestDigest, MountSource, SlotTarget, framework_capability, parse_slot_query,
    span_for_json_pointer,
};
use amber_scenario::{
    BindingEdge, BindingFrom, Component, ComponentId, ProvideRef,
    ResourceDecl as ScenarioResourceDecl, ResourceRef, Scenario, ScenarioExport, SlotRef,
    StorageResourceParams as ScenarioStorageResourceParams, graph::component_path_for,
};
use jsonschema::Validator;
use miette::{Diagnostic, NamedSource, SourceSpan};
use serde_json::Value;
use thiserror::Error;

use super::frontend::{ResolvedNode, ResolvedTree};
use crate::{
    ComponentProvenance, DigestStore, Provenance, config_resolution::render_static_config_string,
    config_templates, store::display_url,
};

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

fn collect_binding_decls(
    id: ComponentId,
    manifest: &Manifest,
    link_index: &LinkIndex,
) -> BTreeMap<String, SlotRef> {
    let mut out = BTreeMap::new();
    for (target, binding) in manifest.bindings() {
        let Some(name) = binding.name.as_ref() else {
            continue;
        };
        let (target_component, slot_name) = match target {
            BindingTarget::SelfSlot(slot) => (id, slot.as_str()),
            BindingTarget::ChildSlot { child, slot } => (link_index.child_id(child), slot.as_str()),
            _ => continue,
        };
        out.insert(
            name.to_string(),
            SlotRef {
                component: target_component,
                name: slot_name.to_string(),
            },
        );
    }
    out
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
    let url = &provenance.for_component(id).resolved_url;
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

    fn config_site(&self) -> ConfigSite {
        config_site_for_component(self.components, self.provenance, self.store, self.id)
            .unwrap_or_else(|| ConfigSite {
                src: unknown_source(),
                span: (0usize, 0usize).into(),
                label: "config here".to_string(),
            })
    }

    fn component(&self) -> &Component {
        component(self.components, self.id)
    }

    fn invalid_value_site(&self, instance_path: &str) -> Option<ConfigSite> {
        let component = self.component();
        let parent = component.parent?;
        component.config.as_ref()?;
        let parent_prov = self.provenance.for_component(parent);
        let stored = self.store.get_source(&parent_prov.resolved_url)?;
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
        let name = crate::store::display_url(&parent_prov.resolved_url);
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

    fn resource_param_site(&self, resource: &str, param: &str) -> Option<ConfigSite> {
        let (src, spans) = source_for_component(self.provenance, self.store, self.id)?;
        let resource_spans = spans.resources.get(resource)?;
        let span = resource_spans
            .params
            .as_ref()
            .and_then(|params| match param {
                "size" => params.size,
                "retention" => params.retention,
                "sharing" => params.sharing,
                _ => None,
            })
            .or_else(|| resource_spans.params.as_ref().map(|params| params.whole))
            .unwrap_or(resource_spans.whole);
        Some(ConfigSite {
            src,
            span,
            label: "resource param here".to_string(),
        })
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
        message: format!("config definition for {component_path}"),
        src,
        span,
        label: "config definition declared here".to_string(),
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

fn declared_items_help(
    component_label: &str,
    item_kind: &str,
    names: impl Iterator<Item = String>,
    empty_help: impl FnOnce() -> String,
) -> String {
    let mut names: Vec<_> = names.collect();
    if names.is_empty() {
        return empty_help();
    }
    names.sort();
    format!(
        "Valid {item_kind} on {component_label}: {}",
        names.into_iter().take(20).collect::<Vec<_>>().join(", ")
    )
}

fn unknown_slot_help(component_label: &str, manifest: &Manifest) -> String {
    declared_items_help(
        component_label,
        "slots",
        manifest.slots().keys().map(|name| name.to_string()),
        || {
            format!(
                "No slots are declared on {component_label}. Declare slots in a `slots: {{ ... \
                 }}` block, or fix the binding target."
            )
        },
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
    declared_items_help(
        &component_label,
        "exports",
        manifest.exports().keys().map(|name| name.to_string()),
        || {
            format!(
                "No exports are declared by {component_label}. Add an `exports: {{ ... }}` entry, \
                 or fix the reference."
            )
        },
    )
}

fn slot_decl_related_span(
    components: &[Option<Component>],
    provenance: &Provenance,
    store: &DigestStore,
    slot_ref: &SlotRef,
    message_prefix: &str,
    label: &str,
    use_kind_span: bool,
) -> Option<RelatedSpan> {
    let (src, slot_spans) = source_for_component(provenance, store, slot_ref.component)?;
    let spans = slot_spans.slots.get(slot_ref.name.as_str())?;
    let span = if use_kind_span {
        spans.kind.unwrap_or(spans.whole)
    } else {
        spans.name
    };
    Some(RelatedSpan {
        message: format!(
            "{message_prefix} `{}` declared on {}",
            slot_ref.name,
            component_path_for(components, slot_ref.component)
        ),
        src,
        span,
        label: label.to_string(),
    })
}

fn storage_mount_index(manifest: &Manifest, slot: &str) -> Option<usize> {
    let program = manifest.program()?;
    program.mounts().iter().position(|mount| {
        matches!(
            &mount.source,
            MountSource::Slot(mount_slot) if mount_slot.as_str() == slot
        )
    })
}

fn mount_source_site(
    provenance: &Provenance,
    store: &DigestStore,
    id: ComponentId,
    mount_index: usize,
) -> Option<(NamedSource<Arc<str>>, SourceSpan)> {
    let prov = provenance.for_component(id);
    let stored = store.get_source(&prov.resolved_url)?;
    let src = NamedSource::new(display_url(&prov.resolved_url), Arc::clone(&stored.source))
        .with_language("json5");
    let root = (0usize, stored.source.len()).into();
    let pointer = format!("/program/mounts/{mount_index}/from");
    let whole_mount_pointer = format!("/program/mounts/{mount_index}");
    let span = span_for_json_pointer(stored.source.as_ref(), root, &pointer)
        .or_else(|| span_for_json_pointer(stored.source.as_ref(), root, &whole_mount_pointer))
        .or_else(|| span_for_json_pointer(stored.source.as_ref(), root, "/program/mounts"))
        .or_else(|| stored.spans.program.as_ref().map(|program| program.whole))
        .unwrap_or((0usize, 0usize).into());
    Some((src, span))
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

    #[error("export `{name}` on {component_path} resolves to unbound slot `{slot}`")]
    #[diagnostic(
        code(linker::export_unbound_slot),
        help("Bind the slot or export a provide/child export instead.")
    )]
    ExportUnboundSlot {
        component_path: String,
        name: String,
        slot: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label(primary, "export declared here")]
        span: SourceSpan,
        #[related]
        related: Vec<RelatedSpan>,
    },

    #[error("type mismatch for slot `{to_component_path}.{slot}`: expected {expected}, got {got}")]
    #[diagnostic(
        code(linker::type_mismatch),
        help(
            "Bind a capability of type `{expected}` to `{to_component_path}.{slot}`, or change \
             the slot/capability `kind`/`profile` so they match."
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

    #[error(
        "storage mount `slots.{slot}` on {component_path} must resolve from a storage resource"
    )]
    #[diagnostic(
        code(linker::storage_mount_requires_resource),
        help(
            "Declare `resources.<name>: {{ kind: \"storage\" }}` and bind it to the mounted \
             storage slot."
        )
    )]
    StorageMountRequiresResource {
        component_path: String,
        slot: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label(primary, "storage mount declared here")]
        span: SourceSpan,
        #[related]
        related: Vec<RelatedSpan>,
    },

    #[error(
        "storage resource `resources.{resource}` on {owner_component_path} fans out to multiple \
         mounted storage slots"
    )]
    #[diagnostic(
        code(linker::storage_resource_fanout),
        help(
            "Allocated storage is exclusive today. Route a distinct storage resource to each \
             mounted sink."
        )
    )]
    StorageResourceFanout {
        owner_component_path: String,
        resource: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label(primary, "one mounted sink is bound here")]
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
        "binding into {component_path}.{slot} must be weak because it depends on external slot \
         `{external}`"
    )]
    #[diagnostic(
        code(linker::external_slot_requires_weak),
        help("Make this binding weak or insert a weak binding upstream.")
    )]
    ExternalSlotRequiresWeakBinding {
        component_path: String,
        slot: String,
        external: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label(primary, "binding must be weak here")]
        span: SourceSpan,
        #[related]
        related: Vec<RelatedSpan>,
    },

    #[error("slot routing cycle detected: {cycle}")]
    #[diagnostic(
        code(linker::slot_cycle),
        help(
            "Break the cycle by making at least one slot `optional: true` or by rewiring the \
             route."
        )
    )]
    SlotCycle {
        cycle: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label(primary, "binding here participates in the cycle")]
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

    #[error("dependency cycle detected: {cycle}")]
    #[diagnostic(
        code(linker::dependency_cycle),
        help("Break the cycle by removing or weakening at least one binding in the cycle.")
    )]
    DependencyCycle {
        cycle: String,
        #[source_code]
        src: Option<NamedSource<Arc<str>>>,
        #[label(primary, "binding here participates in the cycle")]
        span: Option<SourceSpan>,
        #[related]
        related: Vec<RelatedSpan>,
    },
}

#[derive(Clone, Debug)]
enum ResolvedExportSource {
    Provide(ProvideRef),
    Slot(SlotRef),
}

struct ResolvedExport {
    source: ResolvedExportSource,
    decl: CapabilityDecl,
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

    for (id, (c, m)) in components.iter_mut().zip(&manifests).enumerate() {
        let (Some(c), Some(m)) = (c.as_mut(), m.as_ref()) else {
            continue;
        };
        c.program = m.program().cloned();
        c.slots = m
            .slots()
            .iter()
            .map(|(name, decl)| (name.as_str().to_string(), decl.clone()))
            .collect();
        c.provides = m
            .provides()
            .iter()
            .map(|(name, decl)| (name.as_str().to_string(), decl.clone()))
            .collect();
        c.resources.clear();
        c.config_schema = m.config_schema().map(|schema| schema.0.clone());
        c.binding_decls = collect_binding_decls(ComponentId(id), m, &link_index[id]);
        c.metadata = m.metadata().cloned();
    }

    let mut schema_cache: HashMap<ManifestDigest, Arc<Validator>> = HashMap::new();
    let mut errors = Vec::new();

    let composed = validate_config_tree(
        root,
        &components,
        &manifests,
        &provenance,
        store,
        &mut schema_cache,
        &mut errors,
    );
    resolve_resource_params(
        &mut components,
        &manifests,
        &composed,
        &provenance,
        store,
        &mut errors,
    );
    for id in (0..components.len()).map(ComponentId) {
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

    let bindings = collect_bindings(
        &components,
        &manifests,
        &link_index,
        &provenance,
        store,
        &mut errors,
    );

    let root_manifest = manifests[root.0]
        .as_ref()
        .expect("root manifest should exist");
    let root_program_slots = collect_program_slot_uses(root_manifest);

    let mut resolver = SlotResolver::new(
        &components,
        &bindings,
        &provenance,
        store,
        root,
        root_program_slots.clone(),
    );
    let binding_edges = resolve_binding_edges(&mut resolver, &bindings, &mut errors);
    let external_root_slots = resolver.external_root_slots();
    validate_all_slots_bound(
        &components,
        &manifests,
        &binding_edges,
        &external_root_slots,
        root,
        &provenance,
        store,
        &mut errors,
    );
    validate_storage_mounts(
        &components,
        &manifests,
        &bindings,
        &mut resolver,
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

    let mut exports = Vec::new();
    for export_name in root_manifest.exports().keys() {
        let resolved_export =
            resolve_export(&components, &manifests, &link_index, root, export_name)
                .expect("export was validated during linking");
        let export_decl = resolved_export.decl.clone();
        let from = match resolved_export.source {
            ResolvedExportSource::Provide(provide) => Some(provide),
            ResolvedExportSource::Slot(slot) => {
                let resolved = resolver.resolve_slot(&slot, &mut errors);
                match resolved {
                    Some(resolved) => match resolved.from {
                        BindingFrom::Component(provide) => Some(provide),
                        BindingFrom::Resource(resource) => {
                            let (src, span) = export_site(&provenance, store, root, export_name);
                            errors.push(Error::InvalidExport {
                                component_path: describe_component_path(&component_path_for(
                                    &components,
                                    root,
                                )),
                                name: export_name.to_string(),
                                message: format!(
                                    "target resolves to resource `resources.{}`, which cannot be \
                                     exported",
                                    resource.name
                                ),
                                help: "Export a component provide or child export instead."
                                    .to_string(),
                                src,
                                span,
                            });
                            None
                        }
                        BindingFrom::Framework(name) => {
                            let (src, span) = export_site(&provenance, store, root, export_name);
                            errors.push(Error::InvalidExport {
                                component_path: describe_component_path(&component_path_for(
                                    &components,
                                    root,
                                )),
                                name: export_name.to_string(),
                                message: format!(
                                    "target resolves to framework.{name}, which cannot be exported"
                                ),
                                help: "Export a component provide or child export instead."
                                    .to_string(),
                                src,
                                span,
                            });
                            None
                        }
                        BindingFrom::External(slot) => {
                            let (src, span) = export_site(&provenance, store, root, export_name);
                            errors.push(Error::InvalidExport {
                                component_path: describe_component_path(&component_path_for(
                                    &components,
                                    root,
                                )),
                                name: export_name.to_string(),
                                message: format!(
                                    "target resolves to external slot `{}`, which cannot be \
                                     exported",
                                    slot.name
                                ),
                                help: "Export a component provide or child export instead."
                                    .to_string(),
                                src,
                                span,
                            });
                            None
                        }
                    },
                    None => {
                        let (src, span) = export_site(&provenance, store, root, export_name);
                        let related = slot_decl_related_span(
                            &components,
                            &provenance,
                            store,
                            &slot,
                            "slot",
                            "slot declared here",
                            false,
                        )
                        .into_iter()
                        .collect();
                        errors.push(Error::ExportUnboundSlot {
                            component_path: describe_component_path(&component_path_for(
                                &components,
                                root,
                            )),
                            name: export_name.to_string(),
                            slot: slot.name,
                            src,
                            span,
                            related,
                        });
                        None
                    }
                }
            }
        };
        if let Some(from) = from {
            exports.push(ScenarioExport {
                name: export_name.to_string(),
                capability: export_decl,
                from,
            });
        }
    }

    if !errors.is_empty() {
        return Err(Error::Multiple {
            count: errors.len(),
            errors,
        });
    }

    let mut binding_edges = binding_edges;
    if !root_program_slots.is_empty() {
        let mut seen = HashSet::new();
        for edge in &binding_edges {
            if edge.to.component == root {
                seen.insert(edge.to.name.clone());
            }
        }
        for slot in root_program_slots {
            if seen.contains(&slot) {
                continue;
            }
            let slot_ref = SlotRef {
                component: root,
                name: slot.clone(),
            };
            binding_edges.push(BindingEdge {
                name: None,
                from: BindingFrom::External(slot_ref.clone()),
                to: slot_ref,
                weak: true,
            });
        }
    }

    let mut scenario = Scenario {
        root,
        components,
        bindings: binding_edges,
        exports,
    };
    scenario.normalize_order();

    if let Some(err) = dependency_cycle_error(&scenario, &bindings, &provenance, store) {
        return Err(err);
    }
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
        digest: node.digest,
        config: node.config.clone(),
        config_schema: None,
        program: None,
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        resources: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
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

fn validate_config_tree(
    root: ComponentId,
    components: &[Option<Component>],
    manifests: &[Option<Arc<Manifest>>],
    provenance: &Provenance,
    store: &DigestStore,
    schema_cache: &mut HashMap<ManifestDigest, Arc<Validator>>,
    errors: &mut Vec<Error>,
) -> config_templates::ComposedTemplates {
    fn invalid_config_error(
        component_path: String,
        site: &ConfigSite,
        message: impl Into<String>,
        label: Option<String>,
        related: Vec<RelatedSpan>,
    ) -> Error {
        Error::InvalidConfig {
            component_path,
            message: message.into(),
            src: site.src.clone(),
            span: site.span,
            label: label.unwrap_or_else(|| site.label.clone()),
            related,
        }
    }

    // 1) Validate Amber-specific schema constraints for every declared config_schema.
    for id in (0..components.len()).map(ComponentId) {
        let m = manifests[id.0].as_ref().expect("manifest should exist");
        let Some(schema_decl) = m.config_schema() else {
            continue;
        };
        if let Err(err) = rc::validate_config_schema(&schema_decl.0) {
            let component_path = component_path_for(components, id);
            let site = ConfigErrorSite::new(components, provenance, store, id).config_site();
            errors.push(invalid_config_error(
                component_path,
                &site,
                format!("invalid config definition: {err}"),
                None,
                Vec::new(),
            ));
        }
    }

    // 2) Validate config use-sites and program `${config.*}` references.

    fn validate_program_config_refs(
        id: ComponentId,
        components: &[Option<Component>],
        manifests: &[Option<Arc<Manifest>>],
        provenance: &Provenance,
        store: &DigestStore,
        schema: Option<&Value>,
        errors: &mut Vec<Error>,
    ) {
        let m = manifests[id.0].as_ref().expect("manifest should exist");
        let Some(program) = m.program() else {
            return;
        };

        let component_path = component_path_for(components, id);
        let site = ConfigErrorSite::new(components, provenance, store, id).config_site();

        let mut validate_config_ref = |location: String, query: &str| {
            let interp_suffix = if query.is_empty() {
                "".to_string()
            } else {
                format!(".{query}")
            };
            let Some(schema) = schema else {
                errors.push(invalid_config_error(
                    component_path.clone(),
                    &site,
                    format!(
                        "{location} references ${{config{interp_suffix}}}, but this component \
                         does not declare `config_schema`"
                    ),
                    Some("config definition required".to_string()),
                    Vec::new(),
                ));
                return;
            };
            match rc::schema_lookup(schema, query) {
                Ok(rc::SchemaLookup::Found) | Ok(rc::SchemaLookup::Unknown) => {}
                Err(e) => {
                    errors.push(invalid_config_error(
                        component_path.clone(),
                        &site,
                        format!("invalid ${{config{interp_suffix}}} reference in {location}: {e}"),
                        Some("invalid config reference".to_string()),
                        Vec::new(),
                    ));
                }
            }
        };

        if let Some(executable) = program.image_ref() {
            if let Ok(parsed) = executable.parse::<InterpolatedString>() {
                for part in &parsed.parts {
                    let InterpolatedPart::Interpolation { source, query } = part else {
                        continue;
                    };
                    if *source == InterpolationSource::Config {
                        validate_config_ref("program.image".to_string(), query);
                    }
                }
            }
        } else if let Some(executable) = program.path_ref()
            && let Ok(parsed) = executable.parse::<InterpolatedString>()
        {
            for part in &parsed.parts {
                let InterpolatedPart::Interpolation { source, query } = part else {
                    continue;
                };
                if *source == InterpolationSource::Config {
                    validate_config_ref("program.path".to_string(), query);
                }
            }
        }

        // args/env are structured (InterpolatedString), so we never need to re-parse `${...}`.
        let command_location = if program.image_ref().is_some() {
            "program.entrypoint"
        } else {
            "program.args"
        };
        for (arg_idx, item) in program.command().0.iter().enumerate() {
            match item {
                amber_manifest::ProgramArgItem::Arg(arg) => {
                    for part in &arg.parts {
                        let InterpolatedPart::Interpolation { source, query } = part else {
                            continue;
                        };
                        if *source == InterpolationSource::Config {
                            validate_config_ref(format!("{command_location}[{arg_idx}]"), query);
                        }
                    }
                }
                amber_manifest::ProgramArgItem::Group(group) => {
                    if group.when.source() == InterpolationSource::Config {
                        validate_config_ref(
                            format!("{command_location}[{arg_idx}].when"),
                            group.when.query(),
                        );
                    }
                    for (group_idx, arg) in group.argv.0.iter().enumerate() {
                        for part in &arg.parts {
                            let InterpolatedPart::Interpolation { source, query } = part else {
                                continue;
                            };
                            if *source == InterpolationSource::Config {
                                validate_config_ref(
                                    format!("{command_location}[{arg_idx}].argv[{group_idx}]"),
                                    query,
                                );
                            }
                        }
                    }
                }
            }
        }

        for (k, v) in program.env() {
            if let Some(when) = v.when()
                && when.source() == InterpolationSource::Config
            {
                validate_config_ref(format!("program.env.{k}.when"), when.query());
            }
            let location = if v.group().is_some() {
                format!("program.env.{k}.value")
            } else {
                format!("program.env.{k}")
            };
            for part in &v.value().parts {
                let InterpolatedPart::Interpolation { source, query } = part else {
                    continue;
                };
                if *source == InterpolationSource::Config {
                    validate_config_ref(location.clone(), query);
                }
            }
        }
    }

    fn validate_resource_config_refs(
        id: ComponentId,
        components: &[Option<Component>],
        manifests: &[Option<Arc<Manifest>>],
        provenance: &Provenance,
        store: &DigestStore,
        schema: Option<&Value>,
        errors: &mut Vec<Error>,
    ) {
        let m = manifests[id.0].as_ref().expect("manifest should exist");
        let component_path = component_path_for(components, id);
        let site = ConfigErrorSite::new(components, provenance, store, id);

        let mut validate_config_ref =
            |resource_name: &str, param_name: &str, value: &InterpolatedString| {
                for part in &value.parts {
                    let InterpolatedPart::Interpolation { source, query } = part else {
                        continue;
                    };

                    let Some(param_site) = site.resource_param_site(resource_name, param_name)
                    else {
                        continue;
                    };

                    match source {
                        InterpolationSource::Config => {
                            let interp_suffix = if query.is_empty() {
                                "".to_string()
                            } else {
                                format!(".{query}")
                            };
                            let Some(schema) = schema else {
                                errors.push(invalid_config_error(
                                    component_path.clone(),
                                    &param_site,
                                    format!(
                                        "resources.{resource_name}.params.{param_name} references \
                                         ${{config{interp_suffix}}}, but this component does not \
                                         declare `config_schema`"
                                    ),
                                    Some("config definition required".to_string()),
                                    Vec::new(),
                                ));
                                continue;
                            };
                            match rc::schema_lookup(schema, query) {
                                Ok(rc::SchemaLookup::Found) | Ok(rc::SchemaLookup::Unknown) => {}
                                Err(err) => errors.push(invalid_config_error(
                                    component_path.clone(),
                                    &param_site,
                                    format!(
                                        "invalid ${{config{interp_suffix}}} reference in \
                                         resources.{resource_name}.params.{param_name}: {err}"
                                    ),
                                    Some("invalid config reference".to_string()),
                                    Vec::new(),
                                )),
                            }
                        }
                        InterpolationSource::Slots => errors.push(invalid_config_error(
                            component_path.clone(),
                            &param_site,
                            format!(
                                "resources.{resource_name}.params.{param_name} uses \
                                 ${{slots...}}, but resource params only support literal strings \
                                 and ${{config...}}"
                            ),
                            Some("invalid interpolation here".to_string()),
                            Vec::new(),
                        )),
                        InterpolationSource::Bindings => errors.push(invalid_config_error(
                            component_path.clone(),
                            &param_site,
                            format!(
                                "resources.{resource_name}.params.{param_name} uses \
                                 ${{bindings...}}, but resource params only support literal \
                                 strings and ${{config...}}"
                            ),
                            Some("invalid interpolation here".to_string()),
                            Vec::new(),
                        )),
                        other => errors.push(invalid_config_error(
                            component_path.clone(),
                            &param_site,
                            format!(
                                "resources.{resource_name}.params.{param_name} uses unsupported \
                                 interpolation source `{other}`"
                            ),
                            Some("invalid interpolation here".to_string()),
                            Vec::new(),
                        )),
                    }
                }
            };

        for (resource_name, resource) in m.resources() {
            if let Some(size) = resource.params.size.as_ref() {
                validate_config_ref(resource_name.as_str(), "size", size);
            }
            if let Some(retention) = resource.params.retention.as_ref() {
                validate_config_ref(resource_name.as_str(), "retention", retention);
            }
            if let Some(sharing) = resource.params.sharing.as_ref() {
                validate_config_ref(resource_name.as_str(), "sharing", sharing);
            }
        }
    }

    fn required_strings(schema: &Value) -> Vec<String> {
        schema
            .get("required")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect()
    }

    fn properties_map(schema: &Value) -> Option<&serde_json::Map<String, Value>> {
        schema.get("properties")?.as_object()
    }

    fn ensure_required_keys_present(
        schema: &Value,
        template: &rc::ConfigNode,
        at: &str,
    ) -> Result<(), String> {
        let Some(props) = properties_map(schema) else {
            return Ok(());
        };
        let rc::ConfigNode::Object(map) = template else {
            return Ok(());
        };

        for req in required_strings(schema) {
            if !map.contains_key(req.as_str()) {
                let full = if at.is_empty() {
                    format!("config.{req}")
                } else {
                    format!("config.{at}.{req}")
                };
                return Err(format!("missing required field {full}"));
            }
        }

        // Recurse only when both schema and template have an object node; runtime inserts (ConfigRef)
        // have unknown structure until runtime, so we do not check deeper.
        for (k, v) in map {
            let Some(child_schema) = props.get(k) else {
                continue;
            };
            let child_at = if at.is_empty() {
                k.clone()
            } else {
                format!("{at}.{k}")
            };
            if child_schema.get("properties").is_some() && matches!(v, rc::ConfigNode::Object(_)) {
                ensure_required_keys_present(child_schema, v, &child_at)?;
            }
        }
        Ok(())
    }

    fn project_schema_for_partial(schema: &Value, partial: &Value) -> Value {
        match (schema, partial) {
            (Value::Object(schema_map), Value::Object(partial_map)) => {
                let mut out = schema_map.clone();

                // Prune `required` to keys that exist in the partial object.
                if let Some(Value::Array(req)) = schema_map.get("required") {
                    let filtered = req
                        .iter()
                        .filter_map(|v| v.as_str())
                        .filter(|k| partial_map.contains_key(*k))
                        .map(|k| Value::String(k.to_string()))
                        .collect::<Vec<_>>();
                    out.insert("required".to_string(), Value::Array(filtered));
                }

                // Recurse into properties that exist in the partial object.
                if let Some(Value::Object(props)) = schema_map.get("properties") {
                    let mut new_props = props.clone();
                    for (k, child_schema) in props {
                        if let Some(child_partial) = partial_map.get(k) {
                            new_props.insert(
                                k.clone(),
                                project_schema_for_partial(child_schema, child_partial),
                            );
                        }
                    }
                    out.insert("properties".to_string(), Value::Object(new_props));
                }

                Value::Object(out)
            }
            _ => schema.clone(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_jsonschema(
        id: ComponentId,
        components: &[Option<Component>],
        manifests: &[Option<Arc<Manifest>>],
        provenance: &Provenance,
        store: &DigestStore,
        schema_cache: &mut HashMap<ManifestDigest, Arc<Validator>>,
        schema_value: &Value,
        instance: &Value,
        context: &str,
    ) -> Result<(), Error> {
        let c = component(components, id);
        let error_site = ConfigErrorSite::new(components, provenance, store, id);
        let component_path = component_path_for(components, id);
        let mut site = error_site.config_site();
        let mut related = Vec::new();
        if let Some(schema) = error_site.schema_related_site(&component_path) {
            related.push(schema);
        }

        // Cache only the full (declared) schema validator.
        let validator = if let Some(schema_decl) = manifests[id.0]
            .as_ref()
            .expect("manifest should exist")
            .config_schema()
            && std::ptr::eq(schema_value, &schema_decl.0)
        {
            if let Some(v) = schema_cache.get(&c.digest) {
                Arc::clone(v)
            } else {
                let v = Arc::new(jsonschema::validator_for(schema_value).map_err(|e| {
                    invalid_config_error(
                        component_path.clone(),
                        &site,
                        format!("{context}: failed to compile schema: {e}"),
                        None,
                        Vec::new(),
                    )
                })?);
                schema_cache.insert(c.digest, Arc::clone(&v));
                v
            }
        } else {
            Arc::new(jsonschema::validator_for(schema_value).map_err(|e| {
                invalid_config_error(
                    component_path.clone(),
                    &site,
                    format!("{context}: failed to compile projected schema: {e}"),
                    None,
                    Vec::new(),
                )
            })?)
        };

        let mut errs = validator.iter_errors(instance);
        let Some(first) = errs.next() else {
            return Ok(());
        };
        let instance_path = first.instance_path().to_string();
        let mut msgs = vec![first.to_string()];
        msgs.extend(errs.take(7).map(|e| e.to_string()));
        if let Some(value_site) = error_site.invalid_value_site(&instance_path) {
            site = value_site;
        }
        Err(invalid_config_error(
            component_path,
            &site,
            format!("{context}: {}", msgs.join("; ")),
            None,
            related,
        ))
    }

    for id in (0..components.len()).map(ComponentId) {
        let m = manifests[id.0].as_ref().expect("manifest should exist");
        let schema = m.config_schema().map(|s| &s.0);
        validate_program_config_refs(id, components, manifests, provenance, store, schema, errors);
        validate_resource_config_refs(id, components, manifests, provenance, store, schema, errors);
    }

    let composed = config_templates::compose_root_config_templates(root, components);

    for err in &composed.errors {
        let component_path = component_path_for(components, err.component);
        let site = ConfigErrorSite::new(components, provenance, store, err.component).config_site();
        errors.push(invalid_config_error(
            component_path,
            &site,
            err.message.clone(),
            None,
            Vec::new(),
        ));
    }

    for id in (0..components.len()).map(ComponentId) {
        let c = component(components, id);
        let m = manifests[id.0].as_ref().expect("manifest should exist");
        let schema = m.config_schema().map(|s| &s.0);

        let component_path = component_path_for(components, id);
        let site = ConfigErrorSite::new(components, provenance, store, id).config_site();

        let Some(schema) = schema else {
            if c.config.is_some() {
                errors.push(invalid_config_error(
                    component_path.clone(),
                    &site,
                    "config was provided for a component that does not declare `config_schema`",
                    None,
                    Vec::new(),
                ));
            }
            continue;
        };

        let template = composed.templates.get(&id).expect("template should exist");
        let rc::RootConfigTemplate::Node(composed) = template else {
            // Root config is a runtime input when schema exists.
            continue;
        };

        if !composed.is_object() {
            errors.push(invalid_config_error(
                component_path.clone(),
                &site,
                "component config must be an object (non-object config templates are unsupported)",
                None,
                Vec::new(),
            ));
            continue;
        }

        if let Err(msg) = ensure_required_keys_present(schema, composed, "") {
            errors.push(invalid_config_error(
                component_path.clone(),
                &site,
                msg,
                None,
                Vec::new(),
            ));
        }

        // Validate static values at compile time.
        if !composed.contains_runtime() {
            match composed.evaluate_static() {
                Ok(v) => {
                    if let Err(e) = validate_jsonschema(
                        id,
                        components,
                        manifests,
                        provenance,
                        store,
                        schema_cache,
                        schema,
                        &v,
                        "invalid config",
                    ) {
                        errors.push(e);
                    }
                }
                Err(err) => errors.push(invalid_config_error(
                    component_path.clone(),
                    &site,
                    err.to_string(),
                    None,
                    Vec::new(),
                )),
            }
        } else if let Some(partial) = composed.static_subset() {
            let projected = project_schema_for_partial(schema, &partial);
            if let Err(e) = validate_jsonschema(
                id,
                components,
                manifests,
                provenance,
                store,
                schema_cache,
                &projected,
                &partial,
                "invalid static config values",
            ) {
                errors.push(e);
            }
        }
    }
    composed
}

fn resolve_resource_params(
    components: &mut [Option<Component>],
    manifests: &[Option<Arc<Manifest>>],
    composed: &config_templates::ComposedTemplates,
    provenance: &Provenance,
    store: &DigestStore,
    errors: &mut Vec<Error>,
) {
    let components_with_template_errors: HashSet<ComponentId> =
        composed.errors.iter().map(|err| err.component).collect();

    for id in (0..components.len()).map(ComponentId) {
        if components[id.0].is_none() {
            continue;
        }
        let manifest = manifests[id.0].as_ref().expect("manifest should exist");
        let component_path = component_path_for(components, id);
        let site = ConfigErrorSite::new(components, provenance, store, id);
        let template = (!components_with_template_errors.contains(&id))
            .then(|| {
                composed
                    .templates
                    .get(&id)
                    .and_then(rc::RootConfigTemplate::node)
            })
            .flatten();
        let mut resolved_resources = BTreeMap::new();

        for (resource_name, resource) in manifest.resources() {
            let mut resolved = ScenarioResourceDecl {
                kind: resource.kind,
                params: ScenarioStorageResourceParams::default(),
            };

            let mut resolve_param =
                |param_name: &str, value: &Option<InterpolatedString>, out: &mut Option<String>| {
                    let Some(value) = value.as_ref() else {
                        return;
                    };
                    if components_with_template_errors.contains(&id)
                        && value.parts.iter().any(|part| {
                            matches!(
                                part,
                                InterpolatedPart::Interpolation {
                                    source: InterpolationSource::Config,
                                    ..
                                }
                            )
                        })
                    {
                        return;
                    }
                    match render_static_config_string(value, template) {
                        Ok(rendered) => *out = Some(rendered),
                        Err(err) => {
                            let param_site = site
                                .resource_param_site(resource_name.as_str(), param_name)
                                .unwrap_or_else(|| ConfigSite {
                                    src: unknown_source(),
                                    span: (0usize, 0usize).into(),
                                    label: "resource param here".to_string(),
                                });
                            errors.push(Error::InvalidConfig {
                                component_path: component_path.clone(),
                                message: format!(
                                    "failed to resolve \
                                     resources.{resource_name}.params.{param_name}: {err}"
                                ),
                                src: param_site.src,
                                span: param_site.span,
                                label: param_site.label,
                                related: Vec::new(),
                            });
                        }
                    }
                };

            resolve_param("size", &resource.params.size, &mut resolved.params.size);
            resolve_param(
                "retention",
                &resource.params.retention,
                &mut resolved.params.retention,
            );
            resolve_param(
                "sharing",
                &resource.params.sharing,
                &mut resolved.params.sharing,
            );
            resolved_resources.insert(resource_name.as_str().to_string(), resolved);
        }

        components[id.0]
            .as_mut()
            .expect("component should exist")
            .resources = resolved_resources;
    }
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

fn export_site(
    provenance: &Provenance,
    store: &DigestStore,
    component: ComponentId,
    export_name: &ExportName,
) -> (NamedSource<Arc<str>>, SourceSpan) {
    source_for_component(provenance, store, component).map_or_else(
        || (unknown_source(), (0usize, 0usize).into()),
        |(src, spans)| {
            let span = spans
                .exports
                .get(export_name.as_str())
                .map(|e| e.target)
                .unwrap_or((0usize, 0usize).into());
            (src, span)
        },
    )
}

#[derive(Clone, Debug)]
struct BindingOrigin {
    realm: ComponentId,
    target_key: BindingTargetKey,
}

#[derive(Clone, Debug)]
struct BindingSpec {
    name: Option<String>,
    target: SlotRef,
    source: CapabilitySource,
    weak: bool,
    origin: BindingOrigin,
}

struct ResolvedBindingTarget {
    slot_ref: SlotRef,
    slot_decl: CapabilityDecl,
}

#[derive(Clone, Debug)]
enum CapabilitySource {
    Provide(ProvideRef),
    Resource(ResourceRef),
    Slot(SlotRef),
    Framework(amber_manifest::FrameworkCapabilityName),
}

struct ResolvedBindingSource {
    source: CapabilitySource,
    decl: CapabilityDecl,
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
        BindingTarget::SelfSlot(_) => Err(Error::UnsupportedManifestFeature {
            component_path: component_path_for(site.components, site.realm),
            feature: "binding target `self`",
        }),
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
                source: CapabilitySource::Provide(ProvideRef {
                    component: from_id,
                    name: provide_name.to_string(),
                }),
                decl: provide_decl.decl.clone(),
            })
        }
        BindingSource::SelfSlot(slot_name) => {
            let from_id = site.realm;
            let from_manifest = manifests[from_id.0]
                .as_ref()
                .expect("manifest should exist");
            let slot_decl = from_manifest
                .slots()
                .get(slot_name)
                .expect("manifest invariant: self slot exists");
            Ok(ResolvedBindingSource {
                source: CapabilitySource::Slot(SlotRef {
                    component: from_id,
                    name: slot_name.to_string(),
                }),
                decl: slot_decl.decl.clone(),
            })
        }
        BindingSource::Resource(resource_name) => {
            let from_id = site.realm;
            let from_manifest = manifests[from_id.0]
                .as_ref()
                .expect("manifest should exist");
            let resource_decl = from_manifest
                .resources()
                .get(resource_name)
                .expect("manifest invariant: resource exists");
            Ok(ResolvedBindingSource {
                source: CapabilitySource::Resource(ResourceRef {
                    component: from_id,
                    name: resource_name.to_string(),
                }),
                decl: CapabilityDecl::builder().kind(resource_decl.kind).build(),
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
                source: match resolved.source {
                    ResolvedExportSource::Provide(provide) => CapabilitySource::Provide(provide),
                    ResolvedExportSource::Slot(slot) => CapabilitySource::Slot(slot),
                },
                decl: resolved.decl,
            })
        }
        BindingSource::Framework(name) => {
            let spec = framework_capability(name.as_str())
                .expect("manifest invariant: framework capability exists");
            Ok(ResolvedBindingSource {
                source: CapabilitySource::Framework(spec.name.clone()),
                decl: spec.decl.clone(),
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
    let ResolvedBindingSource { source, decl } = source;
    let (src, span) = match &source {
        CapabilitySource::Framework(_) => binding_source_site(provenance, store, realm, target_key),
        CapabilitySource::Provide(_)
        | CapabilitySource::Resource(_)
        | CapabilitySource::Slot(_) => binding_site(provenance, store, realm, target_key),
    }
    .unwrap_or_else(|| (unknown_source(), (0usize, 0usize).into()));

    let mut related = Vec::new();

    let to_id = slot_ref.component;
    if let Some(site) = slot_decl_related_span(
        components,
        provenance,
        store,
        &slot_ref,
        "slot",
        "slot type declared here",
        true,
    ) {
        related.push(site);
    }

    match &source {
        CapabilitySource::Provide(provide_ref) => {
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
        }
        CapabilitySource::Resource(resource_ref) => {
            if let Some((resource_src, _)) =
                source_for_component(provenance, store, resource_ref.component)
            {
                related.push(RelatedSpan {
                    message: format!(
                        "resource `resources.{}` declared on {}",
                        resource_ref.name,
                        component_path_for(components, resource_ref.component)
                    ),
                    src: resource_src,
                    span: (0usize, 0usize).into(),
                    label: "resource declared here".to_string(),
                });
            }
        }
        CapabilitySource::Slot(slot_ref) => {
            if let Some(site) = slot_decl_related_span(
                components,
                provenance,
                store,
                slot_ref,
                "slot",
                "slot type declared here",
                true,
            ) {
                related.push(site);
            }
        }
        CapabilitySource::Framework(_) => {}
    }

    Error::TypeMismatch {
        to_component_path: component_path_for(components, to_id),
        slot: slot_ref.name,
        expected: slot_decl,
        got: decl,
        src,
        span,
        related,
    }
}

fn collect_bindings(
    components: &[Option<Component>],
    manifests: &[Option<Arc<Manifest>>],
    link_index: &[LinkIndex],
    provenance: &Provenance,
    store: &DigestStore,
    errors: &mut Vec<Error>,
) -> Vec<BindingSpec> {
    let mut specs = Vec::new();

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

            if target.slot_decl != source.decl {
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

            specs.push(BindingSpec {
                name: binding.name.as_ref().map(|name| name.to_string()),
                target: target.slot_ref,
                source: source.source,
                weak: binding.weak,
                origin: BindingOrigin { realm, target_key },
            });
        }
    }

    specs
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
                source: ResolvedExportSource::Provide(ProvideRef {
                    component,
                    name: provide_name.to_string(),
                }),
                decl: provide_decl.decl.clone(),
            })
        }
        ExportTarget::SelfSlot(slot_name) => {
            let slot_decl = manifest
                .slots()
                .get(slot_name)
                .expect("manifest invariant: self slot exists");
            Ok(ResolvedExport {
                source: ResolvedExportSource::Slot(SlotRef {
                    component,
                    name: slot_name.to_string(),
                }),
                decl: slot_decl.decl.clone(),
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

#[derive(Clone, Debug)]
struct ResolvedBindingFrom {
    from: BindingFrom,
    weak: bool,
    all_weak: bool,
    nonweak: Option<NonWeakBinding>,
}

#[derive(Clone, Debug)]
enum ResolveState {
    Resolving,
    Resolved(Option<ResolvedBindingFrom>),
}

struct SlotResolver<'a> {
    components: &'a [Option<Component>],
    bindings: &'a [BindingSpec],
    binding_by_target: HashMap<SlotRef, usize>,
    provenance: &'a Provenance,
    store: &'a DigestStore,
    states: HashMap<SlotRef, ResolveState>,
    stack: Vec<SlotRef>,
    root: ComponentId,
    external_root_slots: HashSet<String>,
}

#[derive(Clone, Debug)]
struct NonWeakBinding {
    origin: BindingOrigin,
    target: SlotRef,
}

impl<'a> SlotResolver<'a> {
    fn new(
        components: &'a [Option<Component>],
        bindings: &'a [BindingSpec],
        provenance: &'a Provenance,
        store: &'a DigestStore,
        root: ComponentId,
        root_program_slots: HashSet<String>,
    ) -> Self {
        let mut binding_by_target = HashMap::new();
        for (idx, binding) in bindings.iter().enumerate() {
            binding_by_target.insert(binding.target.clone(), idx);
        }
        Self {
            components,
            bindings,
            binding_by_target,
            provenance,
            store,
            states: HashMap::new(),
            stack: Vec::new(),
            root,
            external_root_slots: root_program_slots,
        }
    }

    fn resolve_source(
        &mut self,
        source: &CapabilitySource,
        errors: &mut Vec<Error>,
    ) -> Option<ResolvedBindingFrom> {
        match source {
            CapabilitySource::Provide(provide) => Some(ResolvedBindingFrom {
                from: BindingFrom::Component(provide.clone()),
                weak: false,
                all_weak: true,
                nonweak: None,
            }),
            CapabilitySource::Resource(resource) => Some(ResolvedBindingFrom {
                from: BindingFrom::Resource(resource.clone()),
                weak: false,
                all_weak: true,
                nonweak: None,
            }),
            CapabilitySource::Framework(name) => Some(ResolvedBindingFrom {
                from: BindingFrom::Framework(name.clone()),
                weak: false,
                all_weak: true,
                nonweak: None,
            }),
            CapabilitySource::Slot(slot) => self.resolve_slot(slot, errors),
        }
    }

    fn resolve_slot(
        &mut self,
        slot: &SlotRef,
        errors: &mut Vec<Error>,
    ) -> Option<ResolvedBindingFrom> {
        if let Some(state) = self.states.get(slot) {
            return match state {
                ResolveState::Resolving => self.handle_cycle(slot, errors),
                ResolveState::Resolved(resolved) => resolved.clone(),
            };
        }

        self.states.insert(slot.clone(), ResolveState::Resolving);
        self.stack.push(slot.clone());

        let resolved = match self.binding_by_target.get(slot) {
            None => {
                if slot.component == self.root {
                    self.external_root_slots.insert(slot.name.clone());
                    Some(ResolvedBindingFrom {
                        from: BindingFrom::External(slot.clone()),
                        weak: false,
                        all_weak: true,
                        nonweak: None,
                    })
                } else {
                    None
                }
            }
            Some(&idx) => {
                let binding = &self.bindings[idx];
                let upstream = self.resolve_source(&binding.source, errors);
                upstream.map(|resolved| {
                    let nonweak = if binding.weak {
                        resolved.nonweak
                    } else {
                        Some(NonWeakBinding {
                            origin: binding.origin.clone(),
                            target: binding.target.clone(),
                        })
                    };
                    ResolvedBindingFrom {
                        from: resolved.from,
                        weak: resolved.weak || binding.weak,
                        all_weak: resolved.all_weak && binding.weak,
                        nonweak,
                    }
                })
            }
        };

        self.stack.pop();
        self.states
            .insert(slot.clone(), ResolveState::Resolved(resolved.clone()));
        resolved
    }

    fn handle_cycle(
        &mut self,
        slot: &SlotRef,
        errors: &mut Vec<Error>,
    ) -> Option<ResolvedBindingFrom> {
        let start = self.stack.iter().position(|s| s == slot)?;
        let cycle_slots = self.stack[start..].to_vec();

        let has_optional = cycle_slots.iter().any(|s| self.slot_optional(s));
        if !has_optional {
            let cycle_labels = cycle_labels(self.components, &cycle_slots);
            let cycle = format_cycle(&cycle_labels);

            let (src, span) = self
                .stack
                .last()
                .and_then(|current| self.binding_by_target.get(current))
                .map(|&idx| {
                    let origin = &self.bindings[idx].origin;
                    binding_site(
                        self.provenance,
                        self.store,
                        origin.realm,
                        &origin.target_key,
                    )
                    .unwrap_or_else(|| (unknown_source(), (0usize, 0usize).into()))
                })
                .unwrap_or_else(|| (unknown_source(), (0usize, 0usize).into()));

            let mut related = Vec::new();
            for slot_ref in &cycle_slots {
                if let Some(site) = slot_decl_related_span(
                    self.components,
                    self.provenance,
                    self.store,
                    slot_ref,
                    "slot",
                    "slot declared here",
                    false,
                ) {
                    related.push(site);
                }
            }

            errors.push(Error::SlotCycle {
                cycle,
                src,
                span,
                related,
            });
        }

        for slot_ref in cycle_slots {
            self.states.insert(slot_ref, ResolveState::Resolved(None));
        }

        None
    }

    fn slot_optional(&self, slot: &SlotRef) -> bool {
        self.components[slot.component.0]
            .as_ref()
            .and_then(|c| c.slots.get(slot.name.as_str()))
            .map(|decl| decl.optional)
            .unwrap_or(false)
    }

    fn slot_kind(&self, slot: &SlotRef) -> Option<CapabilityKind> {
        self.components[slot.component.0]
            .as_ref()
            .and_then(|c| c.slots.get(slot.name.as_str()))
            .map(|decl| decl.decl.kind)
    }

    fn external_root_slots(&self) -> HashSet<String> {
        self.external_root_slots.clone()
    }
}

fn cycle_labels(components: &[Option<Component>], slots: &[SlotRef]) -> Vec<String> {
    slots
        .iter()
        .map(|slot| {
            format!(
                "{}.{}",
                component_path_for(components, slot.component),
                slot.name.as_str()
            )
        })
        .collect()
}

fn format_cycle(parts: &[String]) -> String {
    if parts.is_empty() {
        return "<empty>".to_string();
    }
    let mut out = parts.to_vec();
    out.push(parts[0].clone());
    out.join(" -> ")
}

fn collect_program_slot_uses(manifest: &Manifest) -> HashSet<String> {
    let mut uses = HashSet::new();
    let Some(program) = manifest.program() else {
        return uses;
    };

    let mut used_all = false;
    if let Some(executable) = program.path_ref().or_else(|| program.image_ref())
        && let Ok(parsed) = executable.parse::<InterpolatedString>()
    {
        used_all = add_program_slot_uses(manifest, &mut uses, &parsed);
        if used_all {
            return uses;
        }
    }

    for group in program.command().groups() {
        if group.when.source() == InterpolationSource::Slots {
            used_all = add_program_slot_condition_use(manifest, &mut uses, group.when.query());
            if used_all {
                return uses;
            }
        }
    }

    for item in &program.command().0 {
        match item {
            amber_manifest::ProgramArgItem::Arg(arg) => {
                used_all = add_program_slot_uses(manifest, &mut uses, arg);
                if used_all {
                    return uses;
                }
            }
            amber_manifest::ProgramArgItem::Group(group) => {
                for arg in &group.argv.0 {
                    used_all = add_program_slot_uses(manifest, &mut uses, arg);
                    if used_all {
                        return uses;
                    }
                }
            }
        }
    }

    for value in program.env().values() {
        if let Some(when) = value.when()
            && when.source() == InterpolationSource::Slots
        {
            used_all = add_program_slot_condition_use(manifest, &mut uses, when.query());
            if used_all {
                return uses;
            }
        }
        used_all = add_program_slot_uses(manifest, &mut uses, value.value());
        if used_all {
            return uses;
        }
    }

    for mount in program.mounts() {
        if let MountSource::Slot(slot) = &mount.source
            && manifest.slots().contains_key(slot.as_str())
        {
            uses.insert(slot.clone());
        }
    }

    uses
}

fn add_program_slot_condition_use(
    manifest: &Manifest,
    uses: &mut HashSet<String>,
    query: &str,
) -> bool {
    match parse_slot_query(query) {
        Ok(parsed) => match parsed.target {
            SlotTarget::All => {
                uses.extend(manifest.slots().keys().map(|slot| slot.to_string()));
                true
            }
            SlotTarget::Slot(slot) => {
                if manifest.slots().contains_key(slot) {
                    uses.insert(slot.to_string());
                }
                false
            }
        },
        Err(_) if query.is_empty() => {
            uses.extend(manifest.slots().keys().map(|slot| slot.to_string()));
            true
        }
        Err(_) => false,
    }
}

fn add_program_slot_uses(
    manifest: &Manifest,
    uses: &mut HashSet<String>,
    value: &InterpolatedString,
) -> bool {
    let used_all = value.visit_slot_uses(|slot| {
        if manifest.slots().contains_key(slot) {
            uses.insert(slot.to_string());
        }
    });
    if used_all {
        uses.extend(manifest.slots().keys().map(|s| s.to_string()));
    }
    used_all
}

fn dependency_cycle_error(
    scenario: &Scenario,
    bindings: &[BindingSpec],
    provenance: &Provenance,
    store: &DigestStore,
) -> Option<Error> {
    let Err(cycle) = amber_scenario::graph::topo_order(scenario) else {
        return None;
    };

    let mut ids = cycle.cycle;
    if ids.len() > 1 && ids.first() == ids.last() {
        ids.pop();
    }

    let mut labels = Vec::with_capacity(ids.len());
    for id in &ids {
        labels.push(component_path_for(&scenario.components, *id));
    }
    let cycle_str = format_cycle(&labels);

    let mut origin_by_slot: HashMap<SlotRef, BindingOrigin> = HashMap::new();
    for spec in bindings {
        origin_by_slot
            .entry(spec.target.clone())
            .or_insert(spec.origin.clone());
    }

    let mut edge_by_pair: HashMap<(ComponentId, ComponentId), SlotRef> = HashMap::new();
    for binding in &scenario.bindings {
        let BindingFrom::Component(from) = &binding.from else {
            continue;
        };
        if binding.weak {
            continue;
        }
        if from.component == binding.to.component {
            continue;
        }
        edge_by_pair
            .entry((from.component, binding.to.component))
            .or_insert_with(|| binding.to.clone());
    }

    let mut related = Vec::new();
    let mut primary: Option<(NamedSource<Arc<str>>, SourceSpan)> = None;

    for idx in 0..ids.len() {
        let from = ids[idx];
        let to = ids[(idx + 1) % ids.len()];
        let Some(slot_ref) = edge_by_pair.get(&(from, to)) else {
            continue;
        };
        let Some(origin) = origin_by_slot.get(slot_ref) else {
            continue;
        };
        let Some((src, span)) = binding_site(provenance, store, origin.realm, &origin.target_key)
        else {
            continue;
        };

        let message = format!(
            "binding into {}.{} participates in the cycle",
            component_path_for(&scenario.components, slot_ref.component),
            slot_ref.name
        );

        if primary.is_none() {
            primary = Some((src, span));
        } else {
            related.push(RelatedSpan {
                message,
                src,
                span,
                label: "binding here participates in the cycle".to_string(),
            });
        }
    }

    let (src, span) = primary.map_or((None, None), |(src, span)| (Some(src), Some(span)));

    Some(Error::DependencyCycle {
        cycle: cycle_str,
        src,
        span,
        related,
    })
}

fn resolve_binding_edges(
    resolver: &mut SlotResolver<'_>,
    bindings: &[BindingSpec],
    errors: &mut Vec<Error>,
) -> Vec<BindingEdge> {
    let mut edges = Vec::new();
    for binding in bindings {
        let Some(resolved) = resolver.resolve_source(&binding.source, errors) else {
            continue;
        };

        let all_weak = resolved.all_weak && binding.weak;
        let nonweak = if binding.weak {
            resolved
                .nonweak
                .as_ref()
                .map(|entry| (&entry.origin, &entry.target))
        } else {
            Some((&binding.origin, &binding.target))
        };

        if let BindingFrom::External(slot_ref) = &resolved.from
            && !all_weak
            && resolver.slot_kind(slot_ref) != Some(CapabilityKind::Storage)
        {
            let (origin, target) = nonweak.unwrap_or((&binding.origin, &binding.target));

            let (src, span) = binding_target_site(
                resolver.provenance,
                resolver.store,
                origin.realm,
                &origin.target_key,
            )
            .unwrap_or_else(|| (unknown_source(), (0usize, 0usize).into()));

            let related = slot_decl_related_span(
                resolver.components,
                resolver.provenance,
                resolver.store,
                slot_ref,
                "external slot",
                "slot declared here",
                false,
            )
            .into_iter()
            .collect();

            errors.push(Error::ExternalSlotRequiresWeakBinding {
                component_path: describe_component_path(&component_path_for(
                    resolver.components,
                    target.component,
                )),
                slot: target.name.clone(),
                external: slot_ref.name.clone(),
                src,
                span,
                related,
            });
            continue;
        }

        edges.push(BindingEdge {
            name: binding.name.clone(),
            from: resolved.from,
            to: binding.target.clone(),
            weak: binding.weak || resolved.weak,
        });
    }
    edges
}

#[allow(clippy::too_many_arguments)]
fn validate_all_slots_bound(
    components: &[Option<Component>],
    manifests: &[Option<Arc<Manifest>>],
    bindings: &[BindingEdge],
    external_root_slots: &HashSet<String>,
    root: ComponentId,
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
        for (slot_name, slot_decl) in m.slots().iter() {
            if slot_decl.optional {
                continue;
            }
            if slot_decl.decl.kind == CapabilityKind::Storage
                && storage_mount_index(m, slot_name.as_str()).is_some()
            {
                continue;
            }
            if id == root && external_root_slots.contains(slot_name.as_str()) {
                continue;
            }
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use amber_manifest::Manifest;

    use super::collect_program_slot_uses;

    #[test]
    fn collect_program_slot_uses_includes_slot_conditions() {
        let manifest: Manifest = r#"
            {
              manifest_version: "0.2.0",
              program: {
                image: "app",
                entrypoint: [
                  "app",
                  { when: "slots.api", argv: ["--serve"] },
                ],
              },
              slots: {
                api: { kind: "http" },
              },
            }
        "#
        .parse()
        .expect("manifest");

        assert_eq!(
            collect_program_slot_uses(&manifest),
            HashSet::from(["api".to_string()])
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_storage_mounts(
    components: &[Option<Component>],
    manifests: &[Option<Arc<Manifest>>],
    binding_specs: &[BindingSpec],
    resolver: &mut SlotResolver<'_>,
    provenance: &Provenance,
    store: &DigestStore,
    errors: &mut Vec<Error>,
) {
    let binding_origins: HashMap<_, _> = binding_specs
        .iter()
        .map(|binding| {
            (
                (binding.target.component, binding.target.name.as_str()),
                (binding.origin.realm, binding.origin.target_key.clone()),
            )
        })
        .collect();
    let mut sinks_by_resource: HashMap<ResourceRef, Vec<(ComponentId, String, BindingOrigin)>> =
        HashMap::new();

    for id in (0..components.len()).map(ComponentId) {
        let manifest = manifests[id.0].as_ref().expect("manifest should exist");
        for (slot_name, slot_decl) in manifest.slots().iter() {
            if slot_decl.decl.kind != CapabilityKind::Storage {
                continue;
            }
            let Some(mount_index) = storage_mount_index(manifest, slot_name.as_str()) else {
                continue;
            };
            let slot_ref = SlotRef {
                component: id,
                name: slot_name.to_string(),
            };
            let resolved = resolver.resolve_slot(&slot_ref, errors);
            let Some(resolved) = resolved else {
                let component_path = describe_component_path(&component_path_for(components, id));
                let (src, span) = mount_source_site(provenance, store, id, mount_index)
                    .unwrap_or_else(|| (unknown_source(), (0usize, 0usize).into()));
                let mut related: Vec<_> = component_decl_site(components, provenance, store, id)
                    .into_iter()
                    .collect();
                if let Some(site) = slot_decl_related_span(
                    components,
                    provenance,
                    store,
                    &slot_ref,
                    "storage slot",
                    "storage slot declared here",
                    false,
                ) {
                    related.push(site);
                }
                errors.push(Error::StorageMountRequiresResource {
                    component_path,
                    slot: slot_name.to_string(),
                    src,
                    span,
                    related,
                });
                continue;
            };
            let BindingFrom::Resource(resource) = resolved.from else {
                let component_path = describe_component_path(&component_path_for(components, id));
                let (src, span) = mount_source_site(provenance, store, id, mount_index)
                    .unwrap_or_else(|| (unknown_source(), (0usize, 0usize).into()));
                let mut related: Vec<_> = component_decl_site(components, provenance, store, id)
                    .into_iter()
                    .collect();
                if let Some(site) = slot_decl_related_span(
                    components,
                    provenance,
                    store,
                    &slot_ref,
                    "storage slot",
                    "storage slot declared here",
                    false,
                ) {
                    related.push(site);
                }
                errors.push(Error::StorageMountRequiresResource {
                    component_path,
                    slot: slot_name.to_string(),
                    src,
                    span,
                    related,
                });
                continue;
            };

            if let Some((realm, target_key)) = binding_origins.get(&(id, slot_name.as_str())) {
                sinks_by_resource.entry(resource).or_default().push((
                    id,
                    slot_name.to_string(),
                    BindingOrigin {
                        realm: *realm,
                        target_key: target_key.clone(),
                    },
                ));
            } else {
                sinks_by_resource.entry(resource).or_default().push((
                    id,
                    slot_name.to_string(),
                    BindingOrigin {
                        realm: id,
                        target_key: BindingTargetKey::SelfSlot(slot_name.as_str().into()),
                    },
                ));
            }
        }
    }

    for (resource, sinks) in sinks_by_resource {
        let mut unique_sinks = HashSet::new();
        for (component, slot, _) in &sinks {
            unique_sinks.insert((*component, slot.clone()));
        }
        if unique_sinks.len() <= 1 {
            continue;
        }

        let owner_component_path =
            describe_component_path(&component_path_for(components, resource.component));
        let (src, span) =
            binding_source_site(provenance, store, sinks[0].2.realm, &sinks[0].2.target_key)
                .unwrap_or_else(|| (unknown_source(), (0usize, 0usize).into()));
        let related = sinks
            .iter()
            .skip(1)
            .filter_map(|(_, slot, origin)| {
                binding_source_site(provenance, store, origin.realm, &origin.target_key).map(
                    |(src, span)| RelatedSpan {
                        message: format!("another mounted sink is bound through `slots.{slot}`"),
                        src,
                        span,
                        label: "another mounted sink is bound here".to_string(),
                    },
                )
            })
            .collect();
        errors.push(Error::StorageResourceFanout {
            owner_component_path,
            resource: resource.name,
            src,
            span,
            related,
        });
    }
}
