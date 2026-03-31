use super::*;

pub(super) fn source_for_component(
    provenance: &Provenance,
    store: &DigestStore,
    id: ComponentId,
) -> Option<(NamedSource<Arc<str>>, Arc<amber_manifest::ManifestSpans>)> {
    let url = &provenance.for_component(id).resolved_url;
    store.diagnostic_source(url)
}

pub(super) fn unknown_source() -> NamedSource<Arc<str>> {
    NamedSource::new("<source unavailable>", Arc::from("")).with_language("json5")
}

pub(super) fn component_decl_site(
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

pub(super) fn binding_target_site(
    provenance: &Provenance,
    store: &DigestStore,
    realm: ComponentId,
    target_key: &BindingTargetKey,
) -> Option<(NamedSource<Arc<str>>, SourceSpan)> {
    binding_site_with(provenance, store, realm, target_key, |b| {
        b.slot.or(b.to).unwrap_or(b.whole)
    })
}

pub(super) fn binding_source_site(
    provenance: &Provenance,
    store: &DigestStore,
    realm: ComponentId,
    target_key: &BindingTargetKey,
) -> Option<(NamedSource<Arc<str>>, SourceSpan)> {
    binding_site_with(provenance, store, realm, target_key, |b| {
        b.capability.or(b.from).unwrap_or(b.whole)
    })
}

pub(super) fn binding_site(
    provenance: &Provenance,
    store: &DigestStore,
    realm: ComponentId,
    target_key: &BindingTargetKey,
) -> Option<(NamedSource<Arc<str>>, SourceSpan)> {
    binding_site_with(provenance, store, realm, target_key, |b| b.whole)
}

pub(super) fn binding_site_index(
    provenance: &Provenance,
    store: &DigestStore,
    realm: ComponentId,
    binding_index: usize,
) -> Option<(NamedSource<Arc<str>>, SourceSpan)> {
    binding_site_with_index(provenance, store, realm, binding_index, |b| b.whole)
}

pub(super) struct ConfigSite {
    pub(super) src: NamedSource<Arc<str>>,
    pub(super) span: SourceSpan,
    pub(super) label: String,
}

pub(super) struct ConfigErrorSite<'a> {
    pub(super) components: &'a [Option<Component>],
    pub(super) provenance: &'a Provenance,
    pub(super) store: &'a DigestStore,
    pub(super) id: ComponentId,
}

impl<'a> ConfigErrorSite<'a> {
    pub(super) fn new(
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

    pub(super) fn config_site(&self) -> ConfigSite {
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

    pub(super) fn invalid_value_site(&self, instance_path: &str) -> Option<ConfigSite> {
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
        let name = display_url(&parent_prov.resolved_url);
        Some(ConfigSite {
            src: NamedSource::new(name, Arc::clone(&stored.source)).with_language("json5"),
            span,
            label: "invalid config value here".to_string(),
        })
    }

    pub(super) fn schema_related_site(&self, component_path: &str) -> Option<RelatedSpan> {
        if self.component().parent.is_some() {
            config_schema_site(self.provenance, self.store, self.id, component_path)
        } else {
            None
        }
    }

    pub(super) fn resource_param_site(&self, resource: &str, param: &str) -> Option<ConfigSite> {
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
            let span = component_spans
                .config_key
                .or(component_spans.config)
                .unwrap_or(component_spans.whole);
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
pub(super) struct BindingErrorSite<'a> {
    pub(super) components: &'a [Option<Component>],
    pub(super) provenance: &'a Provenance,
    pub(super) store: &'a DigestStore,
    pub(super) realm: ComponentId,
    pub(super) target_key: &'a BindingTargetKey,
}

impl BindingErrorSite<'_> {
    pub(super) fn unknown_slot(
        self,
        to_id: ComponentId,
        slot: &str,
        to_manifest: &Manifest,
    ) -> Error {
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

pub(super) fn not_exported_help(component_path: &str, manifest: &Manifest) -> String {
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

pub(super) fn slot_decl_related_span(
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

pub(super) fn has_storage_mount(component: &Component, slot: &str) -> bool {
    component
        .program
        .as_ref()
        .is_some_and(|program| {
            program.mounts().iter().any(
                |mount| matches!(mount, ProgramMount::Slot { slot: mount_slot, .. } if mount_slot == slot),
            )
        })
}

pub(super) fn mount_source_site(
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

pub(super) fn endpoint_site(
    provenance: &Provenance,
    store: &DigestStore,
    id: ComponentId,
    endpoint_index: usize,
) -> Option<(NamedSource<Arc<str>>, SourceSpan)> {
    let prov = provenance.for_component(id);
    let stored = store.get_source(&prov.resolved_url)?;
    let src = NamedSource::new(display_url(&prov.resolved_url), Arc::clone(&stored.source))
        .with_language("json5");
    let root = (0usize, stored.source.len()).into();
    let whole_endpoint_pointers = [
        format!("/program/network/endpoints/{endpoint_index}"),
        format!("/program/vm/network/endpoints/{endpoint_index}"),
    ];
    let span = whole_endpoint_pointers
        .iter()
        .find_map(|pointer| span_for_json_pointer(stored.source.as_ref(), root, pointer))
        .or_else(|| {
            span_for_json_pointer(stored.source.as_ref(), root, "/program/network/endpoints")
        })
        .or_else(|| {
            span_for_json_pointer(
                stored.source.as_ref(),
                root,
                "/program/vm/network/endpoints",
            )
        })
        .or_else(|| stored.spans.program.as_ref().map(|program| program.whole))
        .unwrap_or((0usize, 0usize).into());
    Some((src, span))
}

pub(super) fn authored_mount_index(
    mount_source_indices_by_component: &HashMap<ComponentId, Vec<usize>>,
    component: ComponentId,
    lowered_mount_index: usize,
) -> usize {
    mount_source_indices_by_component
        .get(&component)
        .and_then(|source_indices| source_indices.get(lowered_mount_index))
        .copied()
        .unwrap_or(lowered_mount_index)
}

#[derive(Clone, Debug)]
pub(super) enum StorageMountSinkSite {
    Binding(BindingOrigin),
    Mount {
        component: ComponentId,
        authored_mount_index: usize,
    },
}

#[derive(Clone, Debug)]
pub(super) struct StorageMountSink {
    pub(super) component: ComponentId,
    pub(super) sink_id: String,
    pub(super) description: String,
    pub(super) site: StorageMountSinkSite,
}

pub(super) fn storage_mount_sink_site(
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
            authored_mount_index,
        } => mount_source_site(provenance, store, *component, *authored_mount_index),
    }
}
