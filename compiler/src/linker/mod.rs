#![allow(unused_assignments)]
#![allow(clippy::result_large_err)]

mod bindings;
pub(crate) mod manifest_table;
pub(crate) mod program_lowering;
mod sites;

mod provenance;

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

use amber_config as rc;
use amber_manifest::{
    BindingSource, BindingTarget, BindingTargetKey, CapabilityDecl, CapabilityKind, ChildName,
    ChildTemplateAllowedManifests, ExportName, ExportTarget, InterpolatedPart, InterpolatedString,
    InterpolationSource, Manifest, ManifestDigest, ProgramConfigUseSite, framework_capability,
    span_for_json_pointer,
};
use amber_scenario::{
    BindingEdge, BindingFrom, ChildTemplate, ChildTemplateLimits, Component, ComponentId,
    FrameworkRef, ManifestCatalogEntry, ProgramMount, ProvideRef,
    ResourceDecl as ScenarioResourceDecl, ResourceRef, Scenario, ScenarioExport, SlotRef,
    StorageResourceParams as ScenarioStorageResourceParams, TemplateBinding, TemplateConfigField,
    graph::component_path_for,
};
use jsonschema::Validator;
use miette::{Diagnostic, NamedSource, SourceSpan};
pub use provenance::{ComponentProvenance, Provenance};
use serde_json::Value;
use thiserror::Error;

use self::{
    bindings::*,
    program_lowering::{
        ProgramLoweringError, ProgramLoweringSite, lower_program_with_config_analysis,
        validate_lowered_program_mounts,
    },
    sites::*,
};
use crate::{
    DigestStore,
    config::analysis::ScenarioConfigAnalysis,
    frontend::{ResolvedNode, ResolvedTree, store::display_url},
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

    #[error("unsupported program endpoint on {component_path}: {message}")]
    #[diagnostic(code(linker::unsupported_program_endpoint))]
    UnsupportedProgramEndpoint {
        component_path: String,
        message: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label(primary, "endpoint declared here")]
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

struct FlattenState<'a> {
    store: &'a DigestStore,
    manifest_catalog: &'a mut BTreeMap<String, ManifestCatalogEntry>,
    out: &'a mut Vec<Option<Component>>,
    provenance: &'a mut Provenance,
    link_index: &'a mut Vec<LinkIndex>,
}

pub fn link(tree: ResolvedTree, store: &DigestStore) -> Result<(Scenario, Provenance), Error> {
    let mut components = Vec::new();
    let mut link_index = Vec::new();
    let mut provenance = Provenance::default();
    let mut manifest_catalog = BTreeMap::new();
    let root = flatten(
        &tree.root,
        None,
        "/",
        &mut FlattenState {
            store,
            manifest_catalog: &mut manifest_catalog,
            out: &mut components,
            provenance: &mut provenance,
            link_index: &mut link_index,
        },
    );

    debug_assert_eq!(components.len(), provenance.components.len());
    debug_assert_eq!(components.len(), link_index.len());

    let manifests = manifest_table::build_manifest_table(&components, store).map_err(|e| {
        Error::MissingManifest {
            component_path: component_path_for(&components, e.component),
            digest: e.digest,
        }
    })?;

    for (c, m) in components.iter_mut().zip(&manifests) {
        let (Some(c), Some(m)) = (c.as_mut(), m.as_ref()) else {
            continue;
        };
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

    let config_analysis = validate_config_tree(
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
        &config_analysis,
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

    let mut mount_source_indices_by_component: HashMap<ComponentId, Vec<usize>> = HashMap::new();
    for id in (0..components.len()).map(ComponentId) {
        let Some(component) = components[id.0].as_mut() else {
            continue;
        };
        let Some(manifest) = manifests[id.0].as_ref() else {
            continue;
        };
        let Some(program) = manifest.program() else {
            continue;
        };
        let component_config = config_analysis.expect_component(id);
        match lower_program_with_config_analysis(id, program, component_config) {
            Ok(lowered) => {
                if let Err(program_errors) = validate_lowered_program_mounts(
                    &lowered.program,
                    &lowered.mount_source_indices,
                    manifest.config_schema(),
                    manifest.resources(),
                    manifest.slots(),
                    manifest.experimental_features(),
                ) {
                    record_program_lowering_errors(
                        id,
                        &component_path_for(&components, id),
                        &program_errors,
                        &provenance,
                        store,
                        &mut errors,
                    );
                    continue;
                }
                mount_source_indices_by_component.insert(id, lowered.mount_source_indices);
                component.program = Some(lowered.program);
            }
            Err(program_errors) => record_program_lowering_errors(
                id,
                &component_path_for(&components, id),
                &program_errors,
                &provenance,
                store,
                &mut errors,
            ),
        }
    }

    // Keep going after local manifest/config/program validation errors so `check` can still
    // surface independent global diagnostics such as binding-shape and export resolution issues.
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
    let root_program_slots = collect_program_slot_uses(
        components[root.0]
            .as_ref()
            .expect("root component should exist"),
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
        &provenance,
        store,
        &mut errors,
    );
    validate_storage_mounts(
        &components,
        &manifests,
        &bindings,
        &mut resolver,
        &mount_source_indices_by_component,
        &provenance,
        store,
        &mut errors,
    );

    let mut exports = Vec::new();
    for export_name in root_manifest.exports().keys() {
        // Earlier validation already emitted a diagnostic for invalid child-export chains.
        // Skip them here so unrelated earlier errors do not turn `check` into a panic.
        let Ok(resolved_export) =
            resolve_export(&components, &manifests, &link_index, root, export_name)
        else {
            continue;
        };
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
                                BindingFrom::Framework(framework) => {
                                    errors.push(Error::InvalidExport {
                                        component_path: describe_component_path(
                                            &component_path_for(&components, root),
                                        ),
                                        name: export_name.to_string(),
                                        message: format!(
                                            "target resolves to framework.{}, which cannot be \
                                             exported",
                                            framework.capability
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
        manifest_catalog,
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
    state: &mut FlattenState<'_>,
) -> ComponentId {
    let id = ComponentId(state.out.len());

    let authored_moniker: Arc<str> = if parent.is_none() {
        Arc::from("/")
    } else if parent_path == "/" {
        Arc::from(format!("/{}", node.name))
    } else {
        Arc::from(format!("{parent_path}/{}", node.name))
    };

    let moniker = Arc::clone(&authored_moniker).into();
    let child_templates = lower_child_templates(node, state.store, state.manifest_catalog);

    state.out.push(Some(Component {
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
        child_templates,
        metadata: None,
        children: Vec::new(),
    }));
    state.link_index.push(LinkIndex::default());

    state.provenance.components.push(ComponentProvenance {
        authored_moniker: Arc::clone(&authored_moniker).into(),
        declared_ref: node.declared_ref.clone(),
        resolved_url: node.resolved_url.clone(),
        digest: node.digest,
        observed_url: node.observed_url.clone(),
    });

    let mut children = Vec::with_capacity(node.children.len());
    let mut child_by_name = BTreeMap::new();
    for (child_name, child_node) in node.children.iter() {
        let child_id = flatten(child_node, Some(id), authored_moniker.as_ref(), state);
        children.push(child_id);
        let child_name =
            ChildName::try_from(child_name.as_str()).expect("child name should be validated");
        child_by_name.insert(child_name, child_id);
    }

    state.out[id.0]
        .as_mut()
        .expect("component should exist")
        .children = children;
    state.link_index[id.0].child_by_name = child_by_name;
    id
}

fn lower_child_templates(
    node: &ResolvedNode,
    store: &DigestStore,
    manifest_catalog: &mut BTreeMap<String, ManifestCatalogEntry>,
) -> BTreeMap<String, ChildTemplate> {
    let mut out = BTreeMap::new();

    for (template_name, template) in &node.child_templates {
        for manifest in &template.manifests {
            collect_manifest_catalog_entries(&manifest.root, store, manifest_catalog);
        }

        let manifest_keys = template
            .manifests
            .iter()
            .map(|manifest| catalog_key(&manifest.source_ref))
            .collect::<Vec<_>>();

        let (manifest, allowed_manifests) = match (
            template.decl.manifest.as_ref(),
            template.decl.allowed_manifests.as_ref(),
        ) {
            (Some(_), None) => (manifest_keys.first().cloned(), None),
            (None, Some(ChildTemplateAllowedManifests::Refs(_)))
            | (None, Some(ChildTemplateAllowedManifests::Selector(_))) => {
                (None, Some(manifest_keys))
            }
            (Some(_), Some(_)) | (None, None) => unreachable!("manifest validation handles this"),
            (None, Some(_)) => unreachable!("manifest validation handles this"),
        };

        out.insert(
            template_name.clone(),
            ChildTemplate {
                manifest,
                allowed_manifests,
                config: template
                    .decl
                    .config
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.clone(),
                            TemplateConfigField::Prefilled {
                                value: value.clone(),
                            },
                        )
                    })
                    .collect(),
                bindings: template
                    .decl
                    .bindings
                    .iter()
                    .map(|(name, selector)| {
                        (
                            name.clone(),
                            TemplateBinding::Prefilled {
                                selector: selector.clone(),
                            },
                        )
                    })
                    .collect(),
                visible_exports: (!template.decl.visible_exports.is_empty())
                    .then(|| template.decl.visible_exports.clone()),
                limits: template
                    .decl
                    .limits
                    .as_ref()
                    .map(|limits| ChildTemplateLimits {
                        max_live_children: limits.max_live_children,
                        name_pattern: limits.name_pattern.clone(),
                    }),
                possible_backends: template.decl.possible_backends.clone(),
            },
        );
    }

    out
}

fn collect_manifest_catalog_entries(
    node: &ResolvedNode,
    store: &DigestStore,
    manifest_catalog: &mut BTreeMap<String, ManifestCatalogEntry>,
) {
    let key = catalog_key(&node.resolved_url);
    manifest_catalog.entry(key).or_insert_with(|| {
        let manifest = store
            .get(&node.digest)
            .expect("resolved manifest should exist in digest store");
        ManifestCatalogEntry {
            source_ref: node.resolved_url.to_string(),
            digest: node.digest,
            manifest: (*manifest).clone(),
        }
    });

    for child in node.children.values() {
        collect_manifest_catalog_entries(child, store, manifest_catalog);
    }
    for template in node.child_templates.values() {
        for manifest in &template.manifests {
            collect_manifest_catalog_entries(&manifest.root, store, manifest_catalog);
        }
    }
}

fn catalog_key(url: &url::Url) -> String {
    url.to_string()
}

fn validate_config_tree(
    root: ComponentId,
    components: &[Option<Component>],
    manifests: &[Option<Arc<Manifest>>],
    provenance: &Provenance,
    store: &DigestStore,
    schema_cache: &mut HashMap<ManifestDigest, Arc<Validator>>,
    errors: &mut Vec<Error>,
) -> ScenarioConfigAnalysis {
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

        program.visit_config_uses(|location, query| {
            let location = match location {
                ProgramConfigUseSite::MountSource { index } => {
                    format!("program.mounts[{index}].from")
                }
                other => other.to_string(),
            };
            validate_config_ref(location, query);
        });
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

    let analysis = ScenarioConfigAnalysis::from_components(root, components)
        .expect("validated component tree should produce config analysis");

    for err in analysis.template_errors() {
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

        let template = analysis.expect_component(id).template();
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
    analysis
}

fn resolve_resource_params(
    components: &mut [Option<Component>],
    manifests: &[Option<Arc<Manifest>>],
    config_analysis: &ScenarioConfigAnalysis,
    provenance: &Provenance,
    store: &DigestStore,
    errors: &mut Vec<Error>,
) {
    let components_with_template_errors: HashSet<ComponentId> = config_analysis
        .template_errors()
        .iter()
        .map(|err| err.component)
        .collect();

    for id in (0..components.len()).map(ComponentId) {
        if components[id.0].is_none() {
            continue;
        }
        let manifest = manifests[id.0].as_ref().expect("manifest should exist");
        let component_path = component_path_for(components, id);
        let site = ConfigErrorSite::new(components, provenance, store, id);
        let component_config = (!components_with_template_errors.contains(&id))
            .then(|| config_analysis.expect_component(id));
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
                    let Some(component_config) = component_config else {
                        return;
                    };
                    match component_config.render_static_string(value) {
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

fn record_program_lowering_errors(
    component: ComponentId,
    component_path: &str,
    program_errors: &[ProgramLoweringError],
    provenance: &Provenance,
    store: &DigestStore,
    errors: &mut Vec<Error>,
) {
    for program_error in program_errors {
        match program_error.site {
            ProgramLoweringSite::Mount(mount_index) => {
                let (src, span) = mount_source_site(provenance, store, component, mount_index)
                    .unwrap_or_else(|| (unknown_source(), (0usize, 0usize).into()));
                errors.push(Error::UnsupportedProgramMount {
                    component_path: component_path.to_string(),
                    message: program_error.message.clone(),
                    src,
                    span,
                });
            }
            ProgramLoweringSite::Endpoint(endpoint_index) => {
                let (src, span) = endpoint_site(provenance, store, component, endpoint_index)
                    .unwrap_or_else(|| (unknown_source(), (0usize, 0usize).into()));
                errors.push(Error::UnsupportedProgramEndpoint {
                    component_path: component_path.to_string(),
                    message: program_error.message.clone(),
                    src,
                    span,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests;
