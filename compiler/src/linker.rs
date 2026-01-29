#![allow(unused_assignments)]
#![allow(clippy::result_large_err)]

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

use amber_config as rc;
use amber_manifest::{
    BindingSource, BindingTarget, BindingTargetKey, CapabilityDecl, ChildName, ExportName,
    ExportTarget, InterpolatedPart, InterpolationSource, Manifest, ManifestDigest,
    framework_capability,
};
use amber_scenario::{
    BindingEdge, BindingFrom, Component, ComponentId, ProvideRef, Scenario, ScenarioExport,
    SlotRef, graph::component_path_for,
};
use jsonschema::Validator;
use miette::{Diagnostic, NamedSource, SourceSpan};
use serde_json::Value;
use thiserror::Error;

use super::frontend::{ResolvedNode, ResolvedTree};
use crate::{ComponentProvenance, DigestStore, Provenance, config_templates};

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
    }

    let mut schema_cache: HashMap<ManifestDigest, Arc<Validator>> = HashMap::new();
    let mut errors = Vec::new();

    validate_config_tree(
        root,
        &components,
        &manifests,
        &provenance,
        store,
        &mut schema_cache,
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

    let mut resolver = SlotResolver::new(&components, &bindings, &provenance, store);
    let binding_edges = resolve_binding_edges(&mut resolver, &bindings, &mut errors);
    validate_all_slots_bound(
        &components,
        &manifests,
        &binding_edges,
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
                    },
                    None => {
                        let (src, span) = export_site(&provenance, store, root, export_name);
                        let mut related = Vec::new();
                        if let Some((slot_src, slot_spans)) =
                            source_for_component(&provenance, store, slot.component)
                            && let Some(s) = slot_spans.slots.get(slot.name.as_str())
                        {
                            related.push(RelatedSpan {
                                message: format!(
                                    "slot `{}` declared on {}",
                                    slot.name,
                                    component_path_for(&components, slot.component)
                                ),
                                src: slot_src,
                                span: s.name,
                                label: "slot declared here".to_string(),
                            });
                        }
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

    let mut scenario = Scenario {
        root,
        components,
        bindings: binding_edges,
        exports,
    };
    scenario.normalize_order();
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
        program: None,
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
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
) {
    // 1) Validate Amber-specific schema constraints for every declared config_schema.
    for id in (0..components.len()).map(ComponentId) {
        let m = manifests[id.0].as_ref().expect("manifest should exist");
        let Some(schema_decl) = m.config_schema() else {
            continue;
        };
        if let Err(err) = rc::validate_config_schema(&schema_decl.0) {
            let component_path = component_path_for(components, id);
            let site = ConfigErrorSite::new(components, provenance, store, id).config_site();
            errors.push(Error::InvalidConfig {
                component_path,
                message: format!("invalid config definition: {err}"),
                src: site.src,
                span: site.span,
                label: site.label,
                related: Vec::new(),
            });
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

        // entrypoint / env are structured (InterpolatedString), so we never need to re-parse `${...}`.
        for (arg_idx, arg) in program.args.0.iter().enumerate() {
            for part in &arg.parts {
                let InterpolatedPart::Interpolation { source, query } = part else {
                    continue;
                };
                if *source != InterpolationSource::Config {
                    continue;
                }
                let Some(schema) = schema else {
                    errors.push(Error::InvalidConfig {
                        component_path: component_path.clone(),
                        message: format!(
                            "program.entrypoint[{arg_idx}] references ${{config{}}}, but this \
                             component does not declare `config_schema`",
                            if query.is_empty() {
                                "".to_string()
                            } else {
                                format!(".{query}")
                            }
                        ),
                        src: site.src.clone(),
                        span: site.span,
                        label: "config definition required".to_string(),
                        related: Vec::new(),
                    });
                    continue;
                };
                match rc::schema_lookup(schema, query.as_str()) {
                    Ok(rc::SchemaLookup::Found) | Ok(rc::SchemaLookup::Unknown) => {}
                    Err(e) => {
                        errors.push(Error::InvalidConfig {
                            component_path: component_path.clone(),
                            message: format!(
                                "invalid ${{config{}}} reference in \
                                 program.entrypoint[{arg_idx}]: {e}",
                                if query.is_empty() {
                                    "".to_string()
                                } else {
                                    format!(".{query}")
                                }
                            ),
                            src: site.src.clone(),
                            span: site.span,
                            label: "invalid config reference".to_string(),
                            related: Vec::new(),
                        });
                    }
                }
            }
        }

        for (k, v) in &program.env {
            for part in &v.parts {
                let InterpolatedPart::Interpolation { source, query } = part else {
                    continue;
                };
                if *source != InterpolationSource::Config {
                    continue;
                }
                let Some(schema) = schema else {
                    errors.push(Error::InvalidConfig {
                        component_path: component_path.clone(),
                        message: format!(
                            "program.env.{k} references ${{config{}}}, but this component does \
                             not declare `config_schema`",
                            if query.is_empty() {
                                "".to_string()
                            } else {
                                format!(".{query}")
                            }
                        ),
                        src: site.src.clone(),
                        span: site.span,
                        label: "config definition required".to_string(),
                        related: Vec::new(),
                    });
                    continue;
                };
                match rc::schema_lookup(schema, query.as_str()) {
                    Ok(rc::SchemaLookup::Found) | Ok(rc::SchemaLookup::Unknown) => {}
                    Err(e) => {
                        errors.push(Error::InvalidConfig {
                            component_path: component_path.clone(),
                            message: format!(
                                "invalid ${{config{}}} reference in program.env.{k}: {e}",
                                if query.is_empty() {
                                    "".to_string()
                                } else {
                                    format!(".{query}")
                                }
                            ),
                            src: site.src.clone(),
                            span: site.span,
                            label: "invalid config reference".to_string(),
                            related: Vec::new(),
                        });
                    }
                }
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
                    Error::InvalidConfig {
                        component_path: component_path.clone(),
                        message: format!("{context}: failed to compile schema: {e}"),
                        src: site.src.clone(),
                        span: site.span,
                        label: site.label.clone(),
                        related: Vec::new(),
                    }
                })?);
                schema_cache.insert(c.digest, Arc::clone(&v));
                v
            }
        } else {
            Arc::new(
                jsonschema::validator_for(schema_value).map_err(|e| Error::InvalidConfig {
                    component_path: component_path.clone(),
                    message: format!("{context}: failed to compile projected schema: {e}"),
                    src: site.src.clone(),
                    span: site.span,
                    label: site.label.clone(),
                    related: Vec::new(),
                })?,
            )
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
        Err(Error::InvalidConfig {
            component_path,
            message: format!("{context}: {}", msgs.join("; ")),
            src: site.src,
            span: site.span,
            label: site.label,
            related,
        })
    }

    for id in (0..components.len()).map(ComponentId) {
        let m = manifests[id.0].as_ref().expect("manifest should exist");
        let schema = m.config_schema().map(|s| &s.0);
        validate_program_config_refs(id, components, manifests, provenance, store, schema, errors);
    }

    let composed = config_templates::compose_root_config_templates(root, components, manifests);

    for err in &composed.errors {
        let component_path = component_path_for(components, err.component);
        let site = ConfigErrorSite::new(components, provenance, store, err.component).config_site();
        errors.push(Error::InvalidConfig {
            component_path,
            message: err.message.clone(),
            src: site.src,
            span: site.span,
            label: site.label,
            related: Vec::new(),
        });
    }

    for id in (0..components.len()).map(ComponentId) {
        let c = component(components, id);
        let m = manifests[id.0].as_ref().expect("manifest should exist");
        let schema = m.config_schema().map(|s| &s.0);

        let component_path = component_path_for(components, id);
        let site = ConfigErrorSite::new(components, provenance, store, id).config_site();

        let Some(schema) = schema else {
            if c.config.is_some() {
                errors.push(Error::InvalidConfig {
                    component_path: component_path.clone(),
                    message: "config was provided for a component that does not declare \
                              `config_schema`"
                        .to_string(),
                    src: site.src.clone(),
                    span: site.span,
                    label: site.label.clone(),
                    related: Vec::new(),
                });
            }
            continue;
        };

        let template = composed.templates.get(&id).expect("template should exist");
        let rc::RootConfigTemplate::Node(composed) = template else {
            // Root config is a runtime input when schema exists.
            continue;
        };

        if !composed.is_object() {
            errors.push(Error::InvalidConfig {
                component_path: component_path.clone(),
                message: "component config must be an object (non-object config templates are \
                          unsupported)"
                    .to_string(),
                src: site.src.clone(),
                span: site.span,
                label: site.label.clone(),
                related: Vec::new(),
            });
            continue;
        }

        if let Err(msg) = ensure_required_keys_present(schema, composed, "") {
            errors.push(Error::InvalidConfig {
                component_path: component_path.clone(),
                message: msg,
                src: site.src.clone(),
                span: site.span,
                label: site.label.clone(),
                related: Vec::new(),
            });
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
                Err(err) => errors.push(Error::InvalidConfig {
                    component_path: component_path.clone(),
                    message: err.to_string(),
                    src: site.src.clone(),
                    span: site.span,
                    label: site.label.clone(),
                    related: Vec::new(),
                }),
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
        CapabilitySource::Provide(_) | CapabilitySource::Slot(_) => {
            binding_site(provenance, store, realm, target_key)
        }
    }
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
        CapabilitySource::Slot(slot_ref) => {
            if let Some((slot_src, slot_spans)) =
                source_for_component(provenance, store, slot_ref.component)
            {
                let slot_name = slot_ref.name.as_str();
                if let Some(s) = slot_spans.slots.get(slot_name) {
                    let span = s.kind.unwrap_or(s.whole);
                    related.push(RelatedSpan {
                        message: format!(
                            "slot `{slot_name}` declared on {}",
                            component_path_for(components, slot_ref.component)
                        ),
                        src: slot_src,
                        span,
                        label: "slot type declared here".to_string(),
                    });
                }
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
}

impl<'a> SlotResolver<'a> {
    fn new(
        components: &'a [Option<Component>],
        bindings: &'a [BindingSpec],
        provenance: &'a Provenance,
        store: &'a DigestStore,
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
            }),
            CapabilitySource::Framework(name) => Some(ResolvedBindingFrom {
                from: BindingFrom::Framework(name.clone()),
                weak: false,
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
            None => None,
            Some(&idx) => {
                let binding = &self.bindings[idx];
                let upstream = self.resolve_source(&binding.source, errors);
                upstream.map(|resolved| ResolvedBindingFrom {
                    from: resolved.from,
                    weak: resolved.weak || binding.weak,
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
                if let Some((slot_src, slot_spans)) =
                    source_for_component(self.provenance, self.store, slot_ref.component)
                    && let Some(s) = slot_spans.slots.get(slot_ref.name.as_str())
                {
                    let span = s.name;
                    related.push(RelatedSpan {
                        message: format!(
                            "slot `{}` declared on {}",
                            slot_ref.name,
                            component_path_for(self.components, slot_ref.component)
                        ),
                        src: slot_src,
                        span,
                        label: "slot declared here".to_string(),
                    });
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
        edges.push(BindingEdge {
            name: binding.name.clone(),
            from: resolved.from,
            to: binding.target.clone(),
            weak: binding.weak || resolved.weak,
        });
    }
    edges
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
        for (slot_name, slot_decl) in m.slots().iter() {
            if slot_decl.optional {
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
