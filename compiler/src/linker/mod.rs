#![allow(unused_assignments)]
#![allow(clippy::result_large_err)]

mod bindings;
pub(crate) mod manifest_table;
pub(crate) mod program_lowering;
mod sites;

mod provenance;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::Arc,
};

use amber_config as rc;
use amber_manifest::{
    BindingSource, BindingTarget, BindingTargetKey, CapabilityDecl, CapabilityKind, ChildName,
    ComponentDecl, ComponentRef, ConfigSchema, ExportName, ExportTarget, InterpolatedPart,
    InterpolatedString, InterpolationSource, Manifest, ManifestDigest, ManifestRef, OverlayDecl,
    OverlayRef, ProgramConfigUseSite, RawManifest, framework_capability, span_for_json_pointer,
};
use amber_scenario::{
    BindingEdge, BindingFrom, ChildTemplate, ChildTemplateLimits, Component, ComponentId,
    FrameworkRef, ManifestCatalogEntry, Moniker, ProgramMount, ProvideRef,
    ResourceDecl as ScenarioResourceDecl, ResourceRef, Scenario, ScenarioExport, SlotRef,
    StorageResourceParams as ScenarioStorageResourceParams, TemplateBinding, TemplateConfigField,
    graph::component_path_for,
};
use jsonschema::Validator;
use miette::{Diagnostic, NamedSource, SourceSpan};
pub use provenance::{ComponentProvenance, Provenance};
use serde_json::Value;
use thiserror::Error;
use url::Url;

use self::{
    bindings::*,
    program_lowering::{
        LoweredProgramValidation, ProgramLoweringError, ProgramLoweringSite,
        lower_program_with_config_analysis, validate_lowered_program,
    },
    sites::*,
};
use crate::{
    DigestStore,
    config::{analysis::ScenarioConfigAnalysis, validation},
    frontend::{ResolvedNode, ResolvedTree, store::display_url},
    overlays::{OverlayExport, OverlayPlan, OverlayScopePlan},
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

#[derive(Clone, Debug)]
struct ScopeBuild {
    root_id: ComponentId,
    root_moniker: amber_scenario::Moniker,
    manifest_url: Url,
    uses: BTreeMap<String, ResolvedNode>,
    overlays: Vec<OverlayDecl>,
}

#[derive(Clone, Debug)]
enum OverlayExportEndpoint {
    Provide {
        name: String,
        decl: CapabilityDecl,
        resolved_url: Url,
    },
    Slot {
        name: String,
        resolved_url: Url,
    },
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

    #[error("overlay `{overlay}` could not resolve export `{export}` from use `#{use_name}`")]
    #[diagnostic(
        code(compiler::overlay_export_unresolved),
        help(
            "Ensure the used manifest exports this capability and that any child export chain \
             resolves to a real export."
        )
    )]
    OverlayExportUnresolved {
        overlay: Box<str>,
        use_name: Box<str>,
        export: Box<str>,
        #[source_code]
        src: Option<NamedSource<Arc<str>>>,
        #[label(primary, "overlay referenced here")]
        span: Option<SourceSpan>,
    },

    #[error("overlay reference `{overlay}` is invalid: {message}")]
    #[diagnostic(
        code(compiler::invalid_overlay_export),
        help(
            "An overlay reference must target an exported `http` provide with `profile: \
             \"overlay\"`. Update the exported provide or reference a different export."
        )
    )]
    InvalidOverlayExport {
        overlay: Box<str>,
        message: Box<str>,
        #[source_code]
        src: Option<NamedSource<Arc<str>>>,
        #[label(primary, "overlay reference here")]
        span: Option<SourceSpan>,
        #[related]
        related: Vec<RelatedSpan>,
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

    #[error("unsupported program on {component_path}: {message}")]
    #[diagnostic(code(linker::unsupported_program))]
    UnsupportedProgram {
        component_path: String,
        message: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label(primary, "program declared here")]
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

    #[error("invalid config for `use` entry `{use_name}` in {component_path}: {message}")]
    #[diagnostic(code(compiler::invalid_use_config))]
    InvalidUseConfig {
        component_path: String,
        use_name: String,
        message: String,
        #[source_code]
        src: Option<NamedSource<Arc<str>>>,
        #[label(primary, "{label}")]
        span: Option<SourceSpan>,
        label: String,
    },

    #[error("unsupported manifest feature `{feature}` in {component_path}")]
    #[diagnostic(code(linker::unsupported_feature))]
    UnsupportedManifestFeature {
        component_path: String,
        feature: &'static str,
    },

    #[error("invalid child template `{template}` on {component_path}: {message}")]
    #[diagnostic(code(linker::invalid_child_template))]
    InvalidChildTemplate {
        component_path: String,
        template: String,
        message: String,
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
    scope_builds: &'a mut Vec<ScopeBuild>,
}

pub fn link(
    tree: ResolvedTree,
    store: &DigestStore,
) -> Result<(Scenario, Option<OverlayPlan>, Provenance), Error> {
    let mut components = Vec::new();
    let mut link_index = Vec::new();
    let mut provenance = Provenance::default();
    let mut manifest_catalog = BTreeMap::new();
    let mut scope_builds = Vec::new();
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
            scope_builds: &mut scope_builds,
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
                if let Err(program_errors) = validate_lowered_program(LoweredProgramValidation {
                    program: &lowered.program,
                    mount_source_indices: &lowered.mount_source_indices,
                    component_id: Some(id),
                    config_schema: manifest.config_schema(),
                    resources: manifest.resources(),
                    slots: manifest.slots(),
                    enabled_features: manifest.experimental_features(),
                    validate_source_interpolations: false,
                }) {
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
    let root_has_program = components[root.0]
        .as_ref()
        .expect("root component should exist")
        .program
        .is_some();
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
    if root_has_program {
        for slot_name in root_manifest.slots().keys() {
            let _ = resolver.resolve_slot(
                &SlotRef {
                    component: root,
                    name: slot_name.to_string(),
                },
                &mut errors,
            );
        }
    }
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

    let mut binding_edges = binding_edges;
    if root_has_program {
        let mut seen = HashSet::new();
        for edge in &binding_edges {
            if edge.to.component == root {
                seen.insert(edge.to.name.clone());
            }
        }
        let mut external_root_slots = external_root_slots.into_iter().collect::<Vec<_>>();
        external_root_slots.sort();
        for slot in external_root_slots {
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
    let overlays = build_overlays(&scope_builds, &config_analysis, store)?;
    scenario.normalize_order();

    if !errors.is_empty() {
        return Err(Error::Multiple {
            count: errors.len(),
            errors,
        });
    }

    if let Some(err) = dependency_cycle_error(&scenario, &bindings, &provenance, store) {
        return Err(err);
    }
    scenario.assert_invariants();
    if let Some(overlays) = &overlays {
        overlays.scenario.assert_invariants();
    }

    Ok((scenario, overlays, provenance))
}

struct UseConfigError {
    message: String,
    pointer: Option<String>,
}

fn compose_use_config(
    use_config: &Value,
    scope_template: &rc::RootConfigTemplate,
    scope_schema: Option<&serde_json::Value>,
) -> Result<rc::ConfigNode, UseConfigError> {
    let parsed = crate::config::template::parse_instance_config_template_located(
        Some(use_config),
        scope_schema,
    )
    .map_err(|err| UseConfigError {
        message: err.error().to_string(),
        pointer: Some(err.pointer().to_string()),
    })?;
    rc::compose_config_template(parsed, scope_template).map_err(|err| UseConfigError {
        message: err.to_string(),
        pointer: None,
    })
}

fn use_config_error_site(
    store: &DigestStore,
    manifest_url: &Url,
    use_name: &str,
    pointer: Option<&str>,
) -> (Option<NamedSource<Arc<str>>>, Option<SourceSpan>, String) {
    let Some(stored) = store.get_source(manifest_url) else {
        return (None, None, "`use` config declared here".to_string());
    };

    let src = NamedSource::new(display_url(manifest_url), Arc::clone(&stored.source))
        .with_language("json5");
    let Some(use_spans) = stored.spans.uses.get(use_name) else {
        return (Some(src), None, "`use` config declared here".to_string());
    };

    if let (Some(pointer), Some(config_span)) = (pointer, use_spans.config)
        && !pointer.is_empty()
        && let Some(span) = span_for_json_pointer(stored.source.as_ref(), config_span, pointer)
    {
        return (
            Some(src),
            Some(span),
            "invalid config value here".to_string(),
        );
    }

    let span = use_spans
        .config_key
        .or(use_spans.config)
        .or(Some(use_spans.whole));
    (Some(src), span, "`use` config declared here".to_string())
}

fn collect_config_ref_paths(node: &rc::ConfigNode) -> BTreeSet<String> {
    fn go(node: &rc::ConfigNode, out: &mut BTreeSet<String>) {
        use amber_template::TemplatePart;
        match node {
            rc::ConfigNode::ConfigRef(path) => {
                out.insert(path.clone());
            }
            rc::ConfigNode::SymbolicConfigRef(path) => {
                out.insert(path.clone());
            }
            rc::ConfigNode::SymbolicString(value) => {
                let parsed = value.parse::<amber_manifest::InterpolatedString>().ok();
                if let Some(parsed) = parsed {
                    parsed.visit_config_uses(|path| {
                        out.insert(path.to_string());
                    });
                }
            }
            rc::ConfigNode::StringTemplate(parts) => {
                for part in parts {
                    if let TemplatePart::Config { config } = part {
                        out.insert(config.clone());
                    }
                }
            }
            rc::ConfigNode::Array(items) => items.iter().for_each(|n| go(n, out)),
            rc::ConfigNode::Object(map) => map.values().for_each(|n| go(n, out)),
            _ => {}
        }
    }
    let mut paths = BTreeSet::new();
    go(node, &mut paths);
    paths
}

/// Drop paths subsumed by a shorter prefix (e.g. "api.key" when "api" is present).
fn normalize_config_paths(paths: &BTreeSet<String>) -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    let mut last_prefix: Option<&str> = None;
    for path in paths {
        if let Some(prefix) = last_prefix
            && path.starts_with(prefix)
            && path.as_bytes().get(prefix.len()) == Some(&b'.')
        {
            continue;
        }
        last_prefix = Some(path.as_str());
        result.insert(path.clone());
    }
    result
}

fn overlay_display_name(scope_root: &Moniker, alias: &str) -> String {
    if scope_root.as_str() == "/" {
        format!("/{alias}")
    } else {
        format!("{}/{alias}", scope_root.as_str())
    }
}

fn overlays_root_schema_for_paths(root_schema: &Value, paths: &BTreeSet<String>) -> Value {
    // An empty path is the internal sentinel for `${config}` / `$${config}`, meaning the overlay
    // needs the whole root object rather than a property literally named `""`.
    if paths.contains("") {
        return root_schema.clone();
    }

    fn insert_path(
        props: &mut serde_json::Map<String, Value>,
        required: &mut Vec<Value>,
        path: &str,
        leaf_schema: &Value,
        is_required: bool,
    ) {
        match path.split_once('.') {
            Some((head, tail)) => {
                let entry = props
                    .entry(head.to_string())
                    .or_insert_with(|| serde_json::json!({ "type": "object", "properties": {} }));
                if let Value::Object(obj) = entry {
                    obj.entry("properties")
                        .or_insert_with(|| Value::Object(serde_json::Map::new()));
                    let mut nested_required: Vec<Value> = match obj.get("required") {
                        Some(Value::Array(arr)) => arr.clone(),
                        _ => Vec::new(),
                    };
                    if let Some(Value::Object(nested_props)) = obj.get_mut("properties") {
                        insert_path(
                            nested_props,
                            &mut nested_required,
                            tail,
                            leaf_schema,
                            is_required,
                        );
                    }
                    if !nested_required.is_empty() {
                        obj.insert("required".to_string(), Value::Array(nested_required));
                    }
                }
                if is_required && !required.iter().any(|r| r == head) {
                    required.push(Value::String(head.to_string()));
                }
            }
            None => {
                props
                    .entry(path.to_string())
                    .or_insert_with(|| leaf_schema.clone());
                if is_required && !required.iter().any(|r| r == path) {
                    required.push(Value::String(path.to_string()));
                }
            }
        }
    }

    let mut properties = serde_json::Map::new();
    let mut required: Vec<Value> = Vec::new();
    for path in paths {
        let leaf = rc::schema_lookup_ref(root_schema, path)
            .ok()
            .cloned()
            .unwrap_or(Value::Bool(true));
        let is_required = rc::schema_path_is_required(root_schema, path)
            .ok()
            .unwrap_or(false);
        insert_path(&mut properties, &mut required, path, &leaf, is_required);
    }
    let mut schema = serde_json::json!({ "type": "object", "properties": properties });
    if !required.is_empty() {
        schema["required"] = Value::Array(required);
    }
    schema
}

fn build_overlays(
    scope_builds: &[ScopeBuild],
    config_analysis: &ScenarioConfigAnalysis,
    store: &DigestStore,
) -> Result<Option<OverlayPlan>, Error> {
    if scope_builds.is_empty() {
        return Ok(None);
    }

    let overlays_root_url = Url::parse("overlays://root").expect("valid overlays root url");
    let overlays_root_ref = ManifestRef::new(overlays_root_url.clone(), None);

    let mut overlays_children = BTreeMap::new();
    let mut overlays_root_components = BTreeMap::new();
    let mut overlays_root_exports = BTreeMap::new();
    let mut overlays_root_config_paths: BTreeSet<String> = BTreeSet::new();
    let mut scopes = Vec::with_capacity(scope_builds.len());

    for (scope_index, scope) in scope_builds.iter().enumerate() {
        let scope_ca = config_analysis.component(scope.root_id);
        let referenced_uses: BTreeSet<&str> = scope
            .overlays
            .iter()
            .map(|overlay| overlay.overlay.alias.as_str())
            .collect();

        let mut use_child_names = BTreeMap::new();
        for (use_index, (use_name, use_node)) in scope
            .uses
            .iter()
            .filter(|(use_name, _)| referenced_uses.contains(use_name.as_str()))
            .enumerate()
        {
            let child_name = format!("use_{scope_index}_{use_index}");
            let composed_config = match (use_node.config.as_ref(), scope_ca) {
                (Some(raw_config), Some(sa)) => {
                    let composed =
                        compose_use_config(raw_config, sa.template(), sa.component_schema())
                            .map_err(|err| {
                                let (src, span, label) = use_config_error_site(
                                    store,
                                    &scope.manifest_url,
                                    use_name,
                                    err.pointer.as_deref(),
                                );
                                Error::InvalidUseConfig {
                                    component_path: scope.root_moniker.to_string(),
                                    use_name: use_name.clone(),
                                    message: err.message,
                                    src,
                                    span,
                                    label,
                                }
                            })?;
                    overlays_root_config_paths.extend(collect_config_ref_paths(&composed));
                    Some(composed.to_manifest_value())
                }
                _ => use_node.config.clone(),
            };

            let mut child_node = use_node.clone();
            child_node.name = child_name.clone();
            child_node.config = composed_config.clone();
            overlays_children.insert(child_name.clone(), child_node.clone());

            let manifest_ref =
                ManifestRef::new(child_node.resolved_url.clone(), Some(child_node.digest));
            let component_ref = match composed_config {
                Some(config) => ComponentRef::builder()
                    .manifest(manifest_ref)
                    .config(config)
                    .build(),
                None => ComponentRef::builder().manifest(manifest_ref).build(),
            };
            overlays_root_components
                .insert(child_name.clone(), ComponentDecl::Object(component_ref));
            use_child_names.insert(use_name.clone(), child_name);
        }

        let mut overlays = Vec::with_capacity(scope.overlays.len());
        for (overlay_index, overlay) in scope.overlays.iter().enumerate() {
            let overlay_ref = &overlay.overlay;
            let use_node = scope
                .uses
                .get(overlay_ref.alias.as_str())
                .expect("overlay aliases are validated before resolution");
            let endpoint = resolve_overlay_export(store, use_node, overlay_ref.export.as_str())
                .map_err(|()| {
                    let (src, span) =
                        overlay_ref_decl_site(store, &scope.manifest_url, overlay_index);
                    Error::OverlayExportUnresolved {
                        overlay: overlay_ref.to_string().into(),
                        use_name: overlay_ref.alias.clone().into(),
                        export: overlay_ref.export.clone().into(),
                        src,
                        span,
                    }
                })?;
            match &endpoint {
                OverlayExportEndpoint::Provide { decl, .. }
                    if decl.kind == CapabilityKind::Http
                        && decl.profile.as_deref() == Some("overlay") => {}
                OverlayExportEndpoint::Provide { name, decl, .. } => {
                    let (src, span) =
                        overlay_ref_decl_site(store, &scope.manifest_url, overlay_index);
                    return Err(Error::InvalidOverlayExport {
                        overlay: overlay_ref.to_string().into(),
                        message: format!(
                            "export `{}` resolves to provide `{name}` with capability `{decl}`; \
                             expected `kind: \"http\"` and `profile: \"overlay\"`",
                            overlay_ref.export
                        )
                        .into(),
                        src,
                        span,
                        related: overlay_endpoint_related_spans(store, overlay_ref, &endpoint),
                    });
                }
                OverlayExportEndpoint::Slot { name, .. } => {
                    let (src, span) =
                        overlay_ref_decl_site(store, &scope.manifest_url, overlay_index);
                    return Err(Error::InvalidOverlayExport {
                        overlay: overlay_ref.to_string().into(),
                        message: format!(
                            "export `{}` resolves to slot `{name}`; expected an exported provide",
                            overlay_ref.export
                        )
                        .into(),
                        src,
                        span,
                        related: overlay_endpoint_related_spans(store, overlay_ref, &endpoint),
                    });
                }
            }

            let child_name = use_child_names
                .get(overlay_ref.alias.as_str())
                .expect("resolved overlay alias should match a resolved use");
            let export_name =
                ExportName::try_from(format!("overlay_{scope_index}_{overlay_index}"))
                    .expect("synthetic overlay export names are valid");
            overlays_root_exports.insert(
                export_name.to_string(),
                format!("#{child_name}.{}", overlay_ref.export)
                    .parse()
                    .expect("synthetic overlay exports should be valid"),
            );
            overlays.push(OverlayExport {
                export: export_name,
                display_name: overlay_display_name(&scope.root_moniker, &overlay_ref.alias),
            });
        }

        scopes.push(OverlayScopePlan {
            root_moniker: scope.root_moniker.clone(),
            overlays,
        });
    }

    let mut raw_manifest = RawManifest::from(&Manifest::empty());
    raw_manifest.components = overlays_root_components;
    raw_manifest.exports = overlays_root_exports;
    if !overlays_root_config_paths.is_empty() {
        let normalized = normalize_config_paths(&overlays_root_config_paths);
        let root_schema = config_analysis
            .root_schema()
            .cloned()
            .unwrap_or(Value::Bool(true));
        let schema = overlays_root_schema_for_paths(&root_schema, &normalized);
        raw_manifest.config_schema = Some(
            ConfigSchema::new(schema)
                .expect("synthetic overlays root config schema should be valid"),
        );
    }
    let root_manifest: Manifest = raw_manifest
        .try_into()
        .expect("synthetic overlays root manifest should be valid");
    let root_digest = root_manifest.digest();
    store.put(root_digest, Arc::new(root_manifest));

    let overlays_tree = ResolvedTree {
        root: ResolvedNode {
            name: "overlays".to_string(),
            declared_ref: overlays_root_ref.clone(),
            digest: root_digest,
            resolved_url: overlays_root_url,
            observed_url: None,
            config: None,
            children: overlays_children,
            uses: BTreeMap::new(),
            child_templates: BTreeMap::new(),
        },
    };

    // The synthetic overlays artifact is linked like an ordinary tree. This does not recurse
    // because the frontend rejects `use` subtrees that declare nested `use` or `overlays`, so
    // this synthetic tree contains no overlay scopes of its own.
    let (scenario, nested_overlays, provenance) = link(overlays_tree, store)?;
    debug_assert!(
        nested_overlays.is_none(),
        "synthetic overlays artifact should not contain nested overlays"
    );
    Ok(Some(OverlayPlan {
        scenario,
        provenance,
        scopes,
    }))
}

fn resolve_overlay_export(
    store: &DigestStore,
    node: &ResolvedNode,
    export_name: &str,
) -> Result<OverlayExportEndpoint, ()> {
    let manifest = store
        .get(&node.digest)
        .expect("resolved overlay manifest should be in the digest store");
    let Some(target) = manifest.exports().get(export_name) else {
        return Err(());
    };

    match target {
        ExportTarget::SelfProvide(provide_name) => {
            let provide_decl = manifest
                .provides()
                .get(provide_name)
                .expect("manifest invariant: exported provide exists");
            Ok(OverlayExportEndpoint::Provide {
                name: provide_name.to_string(),
                decl: provide_decl.decl.clone(),
                resolved_url: node.resolved_url.clone(),
            })
        }
        ExportTarget::SelfSlot(slot_name) => {
            manifest
                .slots()
                .get(slot_name)
                .expect("manifest invariant: exported slot exists");
            Ok(OverlayExportEndpoint::Slot {
                name: slot_name.to_string(),
                resolved_url: node.resolved_url.clone(),
            })
        }
        ExportTarget::ChildExport { child, export } => {
            let child_node = node
                .children
                .get(child.as_str())
                .expect("manifest invariant: exported child exists");
            resolve_overlay_export(store, child_node, export.as_str())
        }
        _ => Err(()),
    }
}

fn overlay_ref_decl_site(
    store: &DigestStore,
    manifest_url: &Url,
    overlay_index: usize,
) -> (Option<NamedSource<Arc<str>>>, Option<SourceSpan>) {
    store
        .diagnostic_source(manifest_url)
        .map_or((None, None), |(src, spans)| {
            let span = spans
                .overlays
                .get(overlay_index)
                .map(|candidate| candidate.whole)
                .unwrap_or((0usize, 0usize).into());
            (Some(src), Some(span))
        })
}

fn overlay_endpoint_related_spans(
    store: &DigestStore,
    overlay: &OverlayRef,
    endpoint: &OverlayExportEndpoint,
) -> Vec<RelatedSpan> {
    let (resolved_url, name, label) = match endpoint {
        OverlayExportEndpoint::Provide {
            resolved_url, name, ..
        } => (
            resolved_url,
            name,
            "provide resolved from overlay reference",
        ),
        OverlayExportEndpoint::Slot {
            resolved_url, name, ..
        } => (resolved_url, name, "slot resolved from overlay reference"),
    };

    let Some(stored) = store.get_source(resolved_url) else {
        return Vec::new();
    };
    let span = match endpoint {
        OverlayExportEndpoint::Provide { .. } => stored
            .spans
            .provides
            .get(name.as_str())
            .map(|provide| provide.capability.name),
        OverlayExportEndpoint::Slot { .. } => {
            stored.spans.slots.get(name.as_str()).map(|slot| slot.name)
        }
    }
    .unwrap_or((0usize, 0usize).into());

    vec![RelatedSpan {
        message: format!("overlay reference `{overlay}` resolves here"),
        src: NamedSource::new(display_url(resolved_url), stored.source).with_language("json5"),
        span,
        label: label.to_string(),
    }]
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

    let moniker: amber_scenario::Moniker = Arc::clone(&authored_moniker).into();
    let child_templates = lower_child_templates(node, state.store, state.manifest_catalog);
    let manifest = state
        .store
        .get(&node.digest)
        .expect("resolved manifest should exist in digest store");
    if !manifest.overlays().is_empty() {
        state.scope_builds.push(ScopeBuild {
            root_id: id,
            root_moniker: moniker.clone(),
            manifest_url: node.resolved_url.clone(),
            uses: node.uses.clone(),
            overlays: manifest.overlays().to_vec(),
        });
    }

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

        out.insert(
            template_name.clone(),
            ChildTemplate {
                manifests: (!manifest_keys.is_empty()).then_some(manifest_keys),
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

    // 2) Validate config use-sites on authored manifests. Generated overlay IR is validated by
    // the lowered-program verifier because it has no manifest source entry.

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
                Err(err) => {
                    errors.push(invalid_config_error(
                        component_path.clone(),
                        &site,
                        format!(
                            "invalid ${{config{interp_suffix}}} reference in {location}: {err}"
                        ),
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
        let error_site = ConfigErrorSite::new(components, provenance, store, id);
        let template = analysis.expect_component(id).template();
        let digest = c.digest;

        let mut validate_jsonschema = |schema_value: &Value, instance: &Value, context: &str| {
            let validator = if schema.is_some_and(|declared| std::ptr::eq(schema_value, declared)) {
                if let Some(validator) = schema_cache.get(&digest) {
                    Arc::clone(validator)
                } else {
                    let validator =
                        Arc::new(jsonschema::validator_for(schema_value).map_err(|err| {
                            validation::ConfigValidationError::new(format!(
                                "{context}: failed to compile schema: {err}"
                            ))
                        })?);
                    schema_cache.insert(digest, Arc::clone(&validator));
                    validator
                }
            } else {
                Arc::new(jsonschema::validator_for(schema_value).map_err(|err| {
                    validation::ConfigValidationError::new(format!(
                        "{context}: failed to compile schema: {err}"
                    ))
                })?)
            };

            validation::validate_jsonschema_instance(&validator, instance, context)
        };

        for err in validation::validate_component_config_template_with_validator(
            schema,
            template,
            c.config.is_some(),
            &mut validate_jsonschema,
        ) {
            let mut site = error_site.config_site();
            let mut related = Vec::new();
            if let Some(instance_path) = err.instance_path.as_deref() {
                if let Some(value_site) = error_site.invalid_value_site(instance_path) {
                    site = value_site;
                }
                if let Some(schema_site) = error_site.schema_related_site(&component_path) {
                    related.push(schema_site);
                }
            }
            errors.push(invalid_config_error(
                component_path.clone(),
                &site,
                err.message,
                None,
                related,
            ));
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
            ProgramLoweringSite::Program => {
                let (src, span) = program_site(provenance, store, component)
                    .unwrap_or_else(|| (unknown_source(), (0usize, 0usize).into()));
                errors.push(Error::UnsupportedProgram {
                    component_path: component_path.to_string(),
                    message: program_error.message.clone(),
                    src,
                    span,
                });
            }
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
