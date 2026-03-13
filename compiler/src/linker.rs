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
    ManifestDigest, Program, framework_capability, span_for_json_pointer,
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
    ComponentProvenance, DigestStore, Provenance,
    config_resolution::render_static_config_string,
    config_templates,
    program_semantics::{StaticMount, StaticMountKind, StaticMountPlan, analyze_mount_semantics},
    store::display_url,
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

fn binding_site_with_index(
    provenance: &Provenance,
    store: &DigestStore,
    realm: ComponentId,
    binding_index: usize,
    select: impl FnOnce(&amber_manifest::BindingSpans) -> SourceSpan,
) -> Option<(NamedSource<Arc<str>>, SourceSpan)> {
    let (src, spans) = source_for_component(provenance, store, realm)?;
    let span = spans
        .bindings_by_index
        .get(binding_index)
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

fn binding_site_index(
    provenance: &Provenance,
    store: &DigestStore,
    realm: ComponentId,
    binding_index: usize,
) -> Option<(NamedSource<Arc<str>>, SourceSpan)> {
    binding_site_with_index(provenance, store, realm, binding_index, |b| b.whole)
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

fn has_storage_mount(static_mounts: &[StaticMount], slot: &str) -> bool {
    static_mounts
        .iter()
        .any(|mount| matches!(&mount.kind, StaticMountKind::Slot(mount_slot) if mount_slot == slot))
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
    let pointers = [
        format!("/program/mounts/{mount_index}/from"),
        format!("/program/vm/mounts/{mount_index}/from"),
    ];
    let whole_mount_pointers = [
        format!("/program/mounts/{mount_index}"),
        format!("/program/vm/mounts/{mount_index}"),
    ];
    let span = pointers
        .iter()
        .find_map(|pointer| span_for_json_pointer(stored.source.as_ref(), root, pointer))
        .or_else(|| {
            whole_mount_pointers
                .iter()
                .find_map(|pointer| span_for_json_pointer(stored.source.as_ref(), root, pointer))
        })
        .or_else(|| span_for_json_pointer(stored.source.as_ref(), root, "/program/mounts"))
        .or_else(|| span_for_json_pointer(stored.source.as_ref(), root, "/program/vm/mounts"))
        .or_else(|| stored.spans.program.as_ref().map(|program| program.whole))
        .unwrap_or((0usize, 0usize).into());
    Some((src, span))
}

#[derive(Clone, Debug)]
enum StorageMountSinkSite {
    Binding(BindingOrigin),
    Mount {
        component: ComponentId,
        mount_index: usize,
    },
}

#[derive(Clone, Debug)]
struct StorageMountSink {
    component: ComponentId,
    sink_id: String,
    description: String,
    site: StorageMountSinkSite,
}

fn storage_mount_sink_site(
    provenance: &Provenance,
    store: &DigestStore,
    sink: &StorageMountSinkSite,
) -> Option<(NamedSource<Arc<str>>, SourceSpan)> {
    match sink {
        StorageMountSinkSite::Binding(origin) => {
            binding_source_site(provenance, store, origin.realm, &origin.target_key)
        }
        StorageMountSinkSite::Mount {
            component,
            mount_index,
        } => mount_source_site(provenance, store, *component, *mount_index),
    }
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
        "slot range mismatch for `{to_component_path}.{slot}`: target accepts {target_range}, \
         source may provide {source_range}"
    )]
    #[diagnostic(
        code(linker::slot_range_mismatch),
        help(
            "The target slot range must cover the source slot range. Adjust `optional`/`multiple` \
             on the source or target slot so the forwarded fan-in is always valid."
        )
    )]
    SlotRangeMismatch {
        to_component_path: String,
        slot: String,
        target_range: String,
        source_range: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label(
            primary,
            "binding forwards {source_range} into slot accepting {target_range}"
        )]
        span: SourceSpan,
        #[related]
        related: Vec<RelatedSpan>,
    },

    #[error("slot `{slot}` on {component_path} is bound more than once")]
    #[diagnostic(
        code(linker::duplicate_binding_target),
        help("Declare the slot with `multiple: true` or remove the duplicate binding.")
    )]
    DuplicateBindingTarget {
        component_path: String,
        slot: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label(primary, "duplicate binding here")]
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
             storage slot, or mount a local resource directly with `program.mounts: [{{ from: \
             \"resources.<name>\", path: ... }}]`."
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
         mounted storage sinks"
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
        #[label(primary, "one mounted sink uses this resource here")]
        span: SourceSpan,
        #[related]
        related: Vec<RelatedSpan>,
    },

    #[error("unsupported program mount on {component_path}: {message}")]
    #[diagnostic(code(linker::unsupported_program_mount))]
    UnsupportedProgramMount {
        component_path: String,
        message: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label(primary, "mount declared here")]
        span: SourceSpan,
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
        help(
            "Any route that depends on an external slot must be weak overall. Make this binding \
             weak or insert a weak binding upstream."
        )
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

    for (c, m) in components.iter_mut().zip(&manifests) {
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
    let mount_scenario = Scenario {
        root,
        components: components.clone(),
        bindings: Vec::new(),
        exports: Vec::new(),
    };
    let (static_mounts, mount_errors) = analyze_mount_semantics(&mount_scenario);
    record_mount_semantics_errors(&mount_errors, &provenance, store, &components, &mut errors);

    let root_manifest = manifests[root.0]
        .as_ref()
        .expect("root manifest should exist");
    let root_program_slots = collect_program_slot_uses(
        components[root.0]
            .as_ref()
            .expect("root component should exist"),
        static_mounts.component_mounts(root),
    );

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
        &static_mounts,
        &provenance,
        store,
        &mut errors,
    );
    validate_storage_mounts(
        &components,
        &manifests,
        &bindings,
        &mut resolver,
        &static_mounts,
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
                    Some(resolved) => {
                        let (src, span) = export_site(&provenance, store, root, export_name);
                        match resolved.as_slice() {
                            [resolved] => match &resolved.from {
                                BindingFrom::Component(provide) => Some(provide.clone()),
                                BindingFrom::Resource(resource) => {
                                    errors.push(Error::InvalidExport {
                                        component_path: describe_component_path(
                                            &component_path_for(&components, root),
                                        ),
                                        name: export_name.to_string(),
                                        message: format!(
                                            "target resolves to resource `resources.{}`, which \
                                             cannot be exported",
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
                                    errors.push(Error::InvalidExport {
                                        component_path: describe_component_path(
                                            &component_path_for(&components, root),
                                        ),
                                        name: export_name.to_string(),
                                        message: format!(
                                            "target resolves to framework.{name}, which cannot be \
                                             exported"
                                        ),
                                        help: "Export a component provide or child export instead."
                                            .to_string(),
                                        src,
                                        span,
                                    });
                                    None
                                }
                                BindingFrom::External(slot) => {
                                    errors.push(Error::InvalidExport {
                                        component_path: describe_component_path(
                                            &component_path_for(&components, root),
                                        ),
                                        name: export_name.to_string(),
                                        message: format!(
                                            "target resolves to external slot `{}`, which cannot \
                                             be exported",
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
                            _ => {
                                errors.push(Error::InvalidExport {
                                    component_path: describe_component_path(&component_path_for(
                                        &components,
                                        root,
                                    )),
                                    name: export_name.to_string(),
                                    message: format!(
                                        "target resolves to multiple capabilities via slot `{}`",
                                        slot.name
                                    ),
                                    help: "Export a single component provide or child export \
                                           instead."
                                        .to_string(),
                                    src,
                                    span,
                                });
                                None
                            }
                        }
                    }
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

        fn visit_program_string_config_refs(raw: &str, mut visit: impl FnMut(&str)) {
            let Ok(parsed) = raw.parse::<InterpolatedString>() else {
                return;
            };
            for part in &parsed.parts {
                let InterpolatedPart::Interpolation { source, query } = part else {
                    continue;
                };
                if *source == InterpolationSource::Config {
                    visit(query);
                }
            }
        }

        fn visit_vm_scalar_config_refs(
            scalar: &amber_manifest::VmScalarU32,
            mut visit: impl FnMut(&str),
        ) {
            let amber_manifest::VmScalarU32::Interpolated(raw) = scalar else {
                return;
            };
            visit_program_string_config_refs(raw, |query| visit(query));
        }

        fn visit_program_command_config_refs(
            command: &[amber_manifest::ProgramArgItem],
            mut visit: impl FnMut(String, &str),
        ) {
            for (arg_idx, item) in command.iter().enumerate() {
                if let Some(when) = item.when()
                    && when.source() == InterpolationSource::Config
                {
                    visit(format!("[{arg_idx}].when"), when.query());
                }
                item.visit_values(|arg| {
                    for part in &arg.parts {
                        let InterpolatedPart::Interpolation { source, query } = part else {
                            continue;
                        };
                        if *source == InterpolationSource::Config {
                            visit(format!("[{arg_idx}]"), query);
                        }
                    }
                });
            }
        }

        fn visit_program_env_config_refs(
            env: &BTreeMap<String, amber_manifest::ProgramEnvValue>,
            mut visit: impl FnMut(String, &str),
        ) {
            for (key, value) in env {
                if let Some(when) = value.when()
                    && when.source() == InterpolationSource::Config
                {
                    visit(format!("{key}.when"), when.query());
                }
                let location_suffix = if value.when().is_some() || value.each().is_some() {
                    format!("{key}.value")
                } else {
                    key.to_string()
                };
                for part in &value.value().parts {
                    let InterpolatedPart::Interpolation { source, query } = part else {
                        continue;
                    };
                    if *source == InterpolationSource::Config {
                        visit(location_suffix.clone(), query);
                    }
                }
            }
        }

        match program {
            Program::Image(program) => {
                visit_program_string_config_refs(&program.image, |query| {
                    validate_config_ref("program.image".to_string(), query);
                });
                visit_program_command_config_refs(&program.entrypoint.0, |suffix, query| {
                    validate_config_ref(format!("program.entrypoint{suffix}"), query);
                });
                visit_program_env_config_refs(&program.common.env, |suffix, query| {
                    validate_config_ref(format!("program.env.{suffix}"), query);
                });
            }
            Program::Path(program) => {
                visit_program_string_config_refs(&program.path, |query| {
                    validate_config_ref("program.path".to_string(), query);
                });
                visit_program_command_config_refs(&program.args.0, |suffix, query| {
                    validate_config_ref(format!("program.args{suffix}"), query);
                });
                visit_program_env_config_refs(&program.common.env, |suffix, query| {
                    validate_config_ref(format!("program.env.{suffix}"), query);
                });
            }
            Program::Vm(program) => {
                visit_program_string_config_refs(&program.0.image, |query| {
                    validate_config_ref("program.vm.image".to_string(), query);
                });
                visit_vm_scalar_config_refs(&program.0.cpus, |query| {
                    validate_config_ref("program.vm.cpus".to_string(), query);
                });
                visit_vm_scalar_config_refs(&program.0.memory_mib, |query| {
                    validate_config_ref("program.vm.memory_mib".to_string(), query);
                });
                if let Some(raw) = program.0.cloud_init.user_data.as_deref() {
                    visit_program_string_config_refs(raw, |query| {
                        validate_config_ref("program.vm.cloud_init.user_data".to_string(), query);
                    });
                }
                if let Some(raw) = program.0.cloud_init.vendor_data.as_deref() {
                    visit_program_string_config_refs(raw, |query| {
                        validate_config_ref("program.vm.cloud_init.vendor_data".to_string(), query);
                    });
                }
            }
            _ => (),
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
    target: SlotRef,
    source: CapabilitySource,
    weak: bool,
    origin: BindingOrigin,
}

struct ResolvedBindingTarget {
    slot_ref: SlotRef,
    slot_decl: CapabilityDecl,
    slot_range: SlotCardinality,
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
    range: SlotCardinality,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SlotCardinality {
    min: usize,
    max: Option<usize>,
}

impl SlotCardinality {
    const EXACTLY_ONE: Self = Self {
        min: 1,
        max: Some(1),
    };

    fn from_slot_decl(slot: &amber_manifest::SlotDecl) -> Self {
        let min = usize::from(!slot.optional);
        let max = if slot.multiple { None } else { Some(1) };
        Self { min, max }
    }

    fn accepts(self, source: Self) -> bool {
        self.min <= source.min
            && match (self.max, source.max) {
                (None, _) => true,
                (Some(_), None) => false,
                (Some(target_max), Some(source_max)) => target_max >= source_max,
            }
    }

    fn with_weak_binding(self) -> Self {
        Self {
            min: 0,
            max: self.max,
        }
    }
}

impl std::fmt::Display for SlotCardinality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.min, self.max) {
            (0, Some(1)) => f.write_str("0..1"),
            (1, Some(1)) => f.write_str("1"),
            (0, None) => f.write_str("0..*"),
            (1, None) => f.write_str("1..*"),
            (min, Some(max)) if min == max => write!(f, "{min}"),
            (min, Some(max)) => write!(f, "{min}..{max}"),
            (min, None) => write!(f, "{min}..*"),
        }
    }
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
                slot_range: SlotCardinality::from_slot_decl(slot_decl),
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
                range: SlotCardinality::EXACTLY_ONE,
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
                range: SlotCardinality::from_slot_decl(slot_decl),
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
                range: SlotCardinality::EXACTLY_ONE,
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
            let (source, range) = match resolved.source {
                ResolvedExportSource::Provide(provide) => (
                    CapabilitySource::Provide(provide),
                    SlotCardinality::EXACTLY_ONE,
                ),
                ResolvedExportSource::Slot(slot) => {
                    let manifest = manifests[slot.component.0]
                        .as_ref()
                        .expect("manifest should exist");
                    let slot_decl = manifest
                        .slots()
                        .get(slot.name.as_str())
                        .expect("exported slot should exist");
                    (
                        CapabilitySource::Slot(slot),
                        SlotCardinality::from_slot_decl(slot_decl),
                    )
                }
            };
            Ok(ResolvedBindingSource {
                source,
                decl: resolved.decl,
                range,
            })
        }
        BindingSource::Framework(name) => {
            let spec = framework_capability(name.as_str())
                .expect("manifest invariant: framework capability exists");
            Ok(ResolvedBindingSource {
                source: CapabilitySource::Framework(spec.name.clone()),
                decl: spec.decl.clone(),
                range: SlotCardinality::EXACTLY_ONE,
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
        slot_range: _,
    } = target;
    let ResolvedBindingSource {
        source,
        decl,
        range: _,
    } = source;
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

fn slot_range_mismatch_error(
    site: BindingErrorSite<'_>,
    target: &ResolvedBindingTarget,
    accepted_target_range: SlotCardinality,
    source: &ResolvedBindingSource,
) -> Error {
    let (src, span) = binding_site(site.provenance, site.store, site.realm, site.target_key)
        .unwrap_or_else(|| (unknown_source(), (0usize, 0usize).into()));
    let mut related = Vec::new();
    if let Some(site) = slot_decl_related_span(
        site.components,
        site.provenance,
        site.store,
        &target.slot_ref,
        "target slot",
        "target slot declared here",
        true,
    ) {
        related.push(site);
    }
    if let CapabilitySource::Slot(slot_ref) = &source.source
        && let Some(site) = slot_decl_related_span(
            site.components,
            site.provenance,
            site.store,
            slot_ref,
            "source slot",
            "source slot declared here",
            true,
        )
    {
        related.push(site);
    }

    Error::SlotRangeMismatch {
        to_component_path: component_path_for(site.components, target.slot_ref.component),
        slot: target.slot_ref.name.clone(),
        target_range: accepted_target_range.to_string(),
        source_range: source.range.to_string(),
        src,
        span,
        related,
    }
}

fn duplicate_binding_target_error(
    components: &[Option<Component>],
    provenance: &Provenance,
    store: &DigestStore,
    target: &SlotRef,
    first_site: (ComponentId, usize),
    second_site: (ComponentId, usize),
) -> Error {
    let component_path = component_path_for(components, target.component);
    let (src, span) = binding_site_index(provenance, store, second_site.0, second_site.1)
        .unwrap_or_else(|| (unknown_source(), (0usize, 0usize).into()));

    let mut related = Vec::new();
    if let Some((first_src, first_span)) =
        binding_site_index(provenance, store, first_site.0, first_site.1)
    {
        related.push(RelatedSpan {
            message: format!("first binding for `{}` on {}", target.name, component_path),
            src: first_src,
            span: first_span,
            label: "first binding here".to_string(),
        });
    }

    Error::DuplicateBindingTarget {
        component_path,
        slot: target.name.clone(),
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
    let mut seen_singular_targets: HashMap<SlotRef, (ComponentId, usize)> = HashMap::new();

    for realm in (0..components.len()).map(ComponentId) {
        let realm_manifest = manifests[realm.0].as_ref().expect("manifest should exist");

        for (binding_index, binding_decl) in realm_manifest.bindings().iter().enumerate() {
            let target = &binding_decl.target;
            let binding = &binding_decl.binding;
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
            if target.slot_range.max == Some(1) {
                if let Some((first_realm, first_binding_index)) =
                    seen_singular_targets.get(&target.slot_ref)
                {
                    errors.push(duplicate_binding_target_error(
                        components,
                        provenance,
                        store,
                        &target.slot_ref,
                        (*first_realm, *first_binding_index),
                        (realm, binding_index),
                    ));
                    continue;
                }
                seen_singular_targets.insert(target.slot_ref.clone(), (realm, binding_index));
            }
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

            let accepted_target_range = if binding.weak {
                target.slot_range.with_weak_binding()
            } else {
                target.slot_range
            };

            if !accepted_target_range.accepts(source.range) {
                errors.push(slot_range_mismatch_error(
                    site,
                    &target,
                    accepted_target_range,
                    &source,
                ));
                continue;
            }

            specs.push(BindingSpec {
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
    first_nonweak: Option<NonWeakBinding>,
}

#[derive(Clone, Debug)]
enum ResolveState {
    Resolving,
    Resolved(Option<Vec<ResolvedBindingFrom>>),
}

struct SlotResolver<'a> {
    components: &'a [Option<Component>],
    bindings: &'a [BindingSpec],
    binding_by_target: HashMap<SlotRef, Vec<usize>>,
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
            binding_by_target
                .entry(binding.target.clone())
                .or_insert_with(Vec::new)
                .push(idx);
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
    ) -> Option<Vec<ResolvedBindingFrom>> {
        match source {
            CapabilitySource::Provide(provide) => Some(vec![ResolvedBindingFrom {
                from: BindingFrom::Component(provide.clone()),
                weak: false,
                first_nonweak: None,
            }]),
            CapabilitySource::Resource(resource) => Some(vec![ResolvedBindingFrom {
                from: BindingFrom::Resource(resource.clone()),
                weak: false,
                first_nonweak: None,
            }]),
            CapabilitySource::Framework(name) => Some(vec![ResolvedBindingFrom {
                from: BindingFrom::Framework(name.clone()),
                weak: false,
                first_nonweak: None,
            }]),
            CapabilitySource::Slot(slot) => self.resolve_slot(slot, errors),
        }
    }

    fn resolve_slot(
        &mut self,
        slot: &SlotRef,
        errors: &mut Vec<Error>,
    ) -> Option<Vec<ResolvedBindingFrom>> {
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
                    Some(vec![ResolvedBindingFrom {
                        from: BindingFrom::External(slot.clone()),
                        weak: false,
                        first_nonweak: None,
                    }])
                } else {
                    None
                }
            }
            Some(indices) => {
                let indices = indices.clone();
                let mut resolved = Vec::new();
                for idx in indices {
                    let binding = &self.bindings[idx];
                    let Some(upstreams) = self.resolve_source(&binding.source, errors) else {
                        continue;
                    };
                    for upstream in upstreams {
                        let first_nonweak = if binding.weak {
                            upstream.first_nonweak
                        } else {
                            Some(NonWeakBinding {
                                origin: binding.origin.clone(),
                                target: binding.target.clone(),
                            })
                        };
                        resolved.push(ResolvedBindingFrom {
                            from: upstream.from,
                            weak: upstream.weak || binding.weak,
                            first_nonweak,
                        });
                    }
                }
                (!resolved.is_empty()).then_some(resolved)
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
    ) -> Option<Vec<ResolvedBindingFrom>> {
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
                .and_then(|indices| indices.first())
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

fn collect_program_slot_uses(
    component: &Component,
    static_mounts: &[StaticMount],
) -> HashSet<String> {
    let mut uses = HashSet::new();
    let Some(program) = component.program.as_ref() else {
        return uses;
    };

    if program.visit_slot_uses(|slot| {
        if component.slots.contains_key(slot) {
            uses.insert(slot.to_string());
        }
    }) {
        uses.extend(component.slots.keys().cloned());
    }

    for mount in static_mounts {
        if let StaticMountKind::Slot(slot) = &mount.kind
            && component.slots.contains_key(slot.as_str())
        {
            uses.insert(slot.clone());
        }
    }

    uses
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
        let Some(resolved_sources) = resolver.resolve_source(&binding.source, errors) else {
            continue;
        };
        for resolved in resolved_sources {
            let weak = binding.weak || resolved.weak;
            let first_nonweak = if binding.weak {
                resolved.first_nonweak
            } else {
                Some(NonWeakBinding {
                    origin: binding.origin.clone(),
                    target: binding.target.clone(),
                })
            };

            if let BindingFrom::External(slot_ref) = &resolved.from
                && !weak
                && resolver.slot_kind(slot_ref) != Some(CapabilityKind::Storage)
            {
                let (origin, target) = first_nonweak
                    .as_ref()
                    .map(|entry| (&entry.origin, &entry.target))
                    .unwrap_or((&binding.origin, &binding.target));
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
                from: resolved.from,
                to: binding.target.clone(),
                weak,
            });
        }
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
    static_mounts: &StaticMountPlan,
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
                && has_storage_mount(static_mounts.component_mounts(id), slot_name.as_str())
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

#[allow(clippy::too_many_arguments)]
fn validate_storage_mounts(
    components: &[Option<Component>],
    manifests: &[Option<Arc<Manifest>>],
    binding_specs: &[BindingSpec],
    resolver: &mut SlotResolver<'_>,
    static_mounts: &StaticMountPlan,
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
    let mut sinks_by_resource: HashMap<ResourceRef, Vec<StorageMountSink>> = HashMap::new();

    for id in (0..components.len()).map(ComponentId) {
        let manifest = manifests[id.0].as_ref().expect("manifest should exist");
        for mount in static_mounts.component_mounts(id) {
            let mount_index = mount.mount_index;
            match &mount.kind {
                crate::program_semantics::StaticMountKind::Slot(slot_name) => {
                    let Some(slot_decl) = manifest.slots().get(slot_name.as_str()) else {
                        continue;
                    };
                    if slot_decl.decl.kind != CapabilityKind::Storage {
                        continue;
                    }

                    let slot_ref = SlotRef {
                        component: id,
                        name: slot_name.to_string(),
                    };
                    let resolved = resolver.resolve_slot(&slot_ref, errors);
                    let Some(resolved) = resolved else {
                        let component_path =
                            describe_component_path(&component_path_for(components, id));
                        let (src, span) = mount_source_site(provenance, store, id, mount_index)
                            .unwrap_or_else(|| (unknown_source(), (0usize, 0usize).into()));
                        let mut related: Vec<_> =
                            component_decl_site(components, provenance, store, id)
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
                    let [resolved] = resolved.as_slice() else {
                        let component_path =
                            describe_component_path(&component_path_for(components, id));
                        let (src, span) = mount_source_site(provenance, store, id, mount_index)
                            .unwrap_or_else(|| (unknown_source(), (0usize, 0usize).into()));
                        let mut related: Vec<_> =
                            component_decl_site(components, provenance, store, id)
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
                    let BindingFrom::Resource(resource) = &resolved.from else {
                        let component_path =
                            describe_component_path(&component_path_for(components, id));
                        let (src, span) = mount_source_site(provenance, store, id, mount_index)
                            .unwrap_or_else(|| (unknown_source(), (0usize, 0usize).into()));
                        let mut related: Vec<_> =
                            component_decl_site(components, provenance, store, id)
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

                    let site = if let Some((realm, target_key)) =
                        binding_origins.get(&(id, slot_name.as_str()))
                    {
                        StorageMountSinkSite::Binding(BindingOrigin {
                            realm: *realm,
                            target_key: target_key.clone(),
                        })
                    } else {
                        StorageMountSinkSite::Binding(BindingOrigin {
                            realm: id,
                            target_key: BindingTargetKey::SelfSlot(slot_name.as_str().into()),
                        })
                    };
                    sinks_by_resource
                        .entry(resource.clone())
                        .or_default()
                        .push(StorageMountSink {
                            component: id,
                            sink_id: format!("slot:{slot_name}"),
                            description: format!("slots.{slot_name}"),
                            site,
                        });
                }
                crate::program_semantics::StaticMountKind::Resource(resource_name) => {
                    sinks_by_resource
                        .entry(ResourceRef {
                            component: id,
                            name: resource_name.clone(),
                        })
                        .or_default()
                        .push(StorageMountSink {
                            component: id,
                            sink_id: format!("mount:{mount_index}"),
                            description: format!("resources.{resource_name}"),
                            site: StorageMountSinkSite::Mount {
                                component: id,
                                mount_index,
                            },
                        });
                }
                crate::program_semantics::StaticMountKind::Framework(_) => {}
            }
        }
    }

    for (resource, sinks) in sinks_by_resource {
        let mut unique_sinks = HashSet::new();
        for sink in &sinks {
            unique_sinks.insert((sink.component, sink.sink_id.clone()));
        }
        if unique_sinks.len() <= 1 {
            continue;
        }

        let owner_component_path =
            describe_component_path(&component_path_for(components, resource.component));
        let (src, span) = storage_mount_sink_site(provenance, store, &sinks[0].site)
            .unwrap_or_else(|| (unknown_source(), (0usize, 0usize).into()));
        let related = sinks
            .iter()
            .skip(1)
            .filter_map(|sink| {
                storage_mount_sink_site(provenance, store, &sink.site).map(|(src, span)| {
                    RelatedSpan {
                        message: format!("another mounted sink uses `{}`", sink.description),
                        src,
                        span,
                        label: "another mounted sink uses this resource here".to_string(),
                    }
                })
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

fn record_mount_semantics_errors(
    mount_errors: &[crate::program_semantics::MountSemanticsError],
    provenance: &Provenance,
    store: &DigestStore,
    components: &[Option<Component>],
    errors: &mut Vec<Error>,
) {
    for mount_error in mount_errors {
        let component_path = component_path_for(components, mount_error.component);
        let (src, span) = mount_source_site(
            provenance,
            store,
            mount_error.component,
            mount_error.mount_index,
        )
        .unwrap_or_else(|| (unknown_source(), (0usize, 0usize).into()));
        errors.push(Error::UnsupportedProgramMount {
            component_path,
            message: mount_error.message.clone(),
            src,
            span,
        });
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, HashSet},
        sync::Arc,
    };

    use amber_manifest::{Manifest, ManifestDigest};
    use amber_scenario::{Component, ComponentId, Moniker};

    use super::collect_program_slot_uses;
    use crate::program_semantics::{StaticMount, StaticMountKind};

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
        let component = Component {
            id: ComponentId(0),
            parent: None,
            moniker: Moniker::from(Arc::<str>::from("/")),
            digest: ManifestDigest::new([0; 32]),
            config: None,
            config_schema: None,
            program: manifest.program().cloned(),
            slots: manifest
                .slots()
                .iter()
                .map(|(name, decl)| (name.to_string(), decl.clone()))
                .collect(),
            provides: BTreeMap::new(),
            resources: BTreeMap::new(),
            metadata: None,
            children: Vec::new(),
        };

        assert_eq!(
            collect_program_slot_uses(&component, &[]),
            HashSet::from(["api".to_string()])
        );
    }

    #[test]
    fn collect_program_slot_uses_includes_static_mount_slots() {
        let manifest: Manifest = r#"
            {
              manifest_version: "0.3.0",
              program: {
                image: "app",
                entrypoint: ["app"],
                mounts: [
                  { path: "/var/lib/app", from: "${config.mount_source}" },
                ],
              },
              slots: {
                state: { kind: "storage" },
              },
            }
        "#
        .parse()
        .expect("manifest");
        let component = Component {
            id: ComponentId(0),
            parent: None,
            moniker: Moniker::from(Arc::<str>::from("/")),
            digest: ManifestDigest::new([0; 32]),
            config: None,
            config_schema: None,
            program: manifest.program().cloned(),
            slots: manifest
                .slots()
                .iter()
                .map(|(name, decl)| (name.to_string(), decl.clone()))
                .collect(),
            provides: BTreeMap::new(),
            resources: BTreeMap::new(),
            metadata: None,
            children: Vec::new(),
        };

        assert_eq!(
            collect_program_slot_uses(
                &component,
                &[StaticMount {
                    mount_index: 0,
                    path: "/var/lib/app".to_string(),
                    kind: StaticMountKind::Slot("state".to_string()),
                }],
            ),
            HashSet::from(["state".to_string()])
        );
    }
}
