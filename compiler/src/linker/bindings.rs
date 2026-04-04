use super::*;

#[derive(Clone, Debug)]
pub(super) struct BindingOrigin {
    pub(super) realm: ComponentId,
    pub(super) target_key: BindingTargetKey,
}

#[derive(Clone, Debug)]
pub(super) struct BindingSpec {
    target: SlotRef,
    source: CapabilitySource,
    weak: bool,
    origin: BindingOrigin,
}

struct ResolvedBindingTarget {
    pub(super) slot_ref: SlotRef,
    pub(super) slot_decl: CapabilityDecl,
    pub(super) slot_range: SlotCardinality,
}

#[derive(Clone, Debug)]
enum CapabilitySource {
    Provide(ProvideRef),
    Resource(ResourceRef),
    Slot(SlotRef),
    Framework(FrameworkRef),
}

struct ResolvedBindingSource {
    pub(super) source: CapabilitySource,
    pub(super) decl: CapabilityDecl,
    pub(super) range: SlotCardinality,
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

fn effective_self_slot_range(
    components: &[Option<Component>],
    manifests: &[Option<Arc<Manifest>>],
    link_index: &[LinkIndex],
    realm: ComponentId,
    slot_name: &str,
) -> SlotCardinality {
    let manifest = manifests[realm.0].as_ref().expect("manifest should exist");
    let slot_decl = manifest
        .slots()
        .get(slot_name)
        .expect("manifest invariant: self slot exists");
    let declared = SlotCardinality::from_slot_decl(slot_decl);
    if declared == SlotCardinality::EXACTLY_ONE {
        return declared;
    }

    guaranteed_incoming_exact_slot_binding_range(
        components, manifests, link_index, realm, slot_name,
    )
    .unwrap_or(declared)
}

fn guaranteed_incoming_exact_slot_binding_range(
    components: &[Option<Component>],
    manifests: &[Option<Arc<Manifest>>],
    link_index: &[LinkIndex],
    realm: ComponentId,
    slot_name: &str,
) -> Option<SlotCardinality> {
    let component = component(components, realm);
    let parent = component.parent?;
    let parent_manifest = manifests[parent.0].as_ref().expect("manifest should exist");
    let child_name = component_local_name(component);

    parent_manifest
        .bindings()
        .iter()
        .filter(|binding| !binding.binding.weak)
        .find_map(|binding| match (&binding.target, &binding.binding.from) {
            (BindingTarget::ChildSlot { child, slot }, source)
                if child.as_str() == child_name && slot.as_str() == slot_name =>
            {
                source_guaranteed_exact_range(components, manifests, link_index, parent, source)
            }
            _ => None,
        })
}

fn source_guaranteed_exact_range(
    components: &[Option<Component>],
    manifests: &[Option<Arc<Manifest>>],
    link_index: &[LinkIndex],
    realm: ComponentId,
    source: &BindingSource,
) -> Option<SlotCardinality> {
    match source {
        BindingSource::SelfProvide(_)
        | BindingSource::Resource(_)
        | BindingSource::Framework(_) => Some(SlotCardinality::EXACTLY_ONE),
        BindingSource::SelfSlot(slot_name) => {
            let range = effective_self_slot_range(
                components,
                manifests,
                link_index,
                realm,
                slot_name.as_str(),
            );
            (range == SlotCardinality::EXACTLY_ONE).then_some(range)
        }
        BindingSource::ChildExport { .. } => None,
        _ => None,
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
                range: effective_self_slot_range(
                    site.components,
                    manifests,
                    link_index,
                    from_id,
                    slot_name.as_str(),
                ),
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
                source: CapabilitySource::Framework(FrameworkRef {
                    authority: site.realm,
                    capability: spec.name.clone(),
                }),
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

pub(super) fn collect_bindings(
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

pub(super) fn child_component_id(
    link_index: &[LinkIndex],
    realm: ComponentId,
    child: &ChildName,
) -> ComponentId {
    link_index[realm.0].child_id(child)
}

pub(super) fn resolve_export(
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
pub(super) struct ResolvedBindingFrom {
    pub(super) from: BindingFrom,
    pub(super) weak: bool,
    pub(super) first_nonweak: Option<NonWeakBinding>,
}

#[derive(Clone, Debug)]
enum ResolveState {
    Resolving,
    Resolved(Option<Vec<ResolvedBindingFrom>>),
}

pub(super) struct SlotResolver<'a> {
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
pub(super) struct NonWeakBinding {
    pub(super) origin: BindingOrigin,
    pub(super) target: SlotRef,
}

impl<'a> SlotResolver<'a> {
    pub(super) fn new(
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
            CapabilitySource::Framework(framework) => Some(vec![ResolvedBindingFrom {
                from: BindingFrom::Framework(framework.clone()),
                weak: false,
                first_nonweak: None,
            }]),
            CapabilitySource::Slot(slot) => self.resolve_slot(slot, errors),
        }
    }

    pub(super) fn resolve_slot(
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

    pub(super) fn external_root_slots(&self) -> HashSet<String> {
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

pub(super) fn collect_program_slot_uses(component: &Component) -> HashSet<String> {
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

    uses
}

pub(super) fn dependency_cycle_error(
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

pub(super) fn resolve_binding_edges(
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
pub(super) fn validate_all_slots_bound(
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
        let component = components[id.0].as_ref().expect("component should exist");
        for (slot_name, slot_decl) in m.slots().iter() {
            if slot_decl.optional {
                continue;
            }
            if slot_decl.decl.kind == CapabilityKind::Storage
                && has_storage_mount(component, slot_name.as_str())
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
pub(super) fn validate_storage_mounts(
    components: &[Option<Component>],
    manifests: &[Option<Arc<Manifest>>],
    binding_specs: &[BindingSpec],
    resolver: &mut SlotResolver<'_>,
    mount_source_indices_by_component: &HashMap<ComponentId, Vec<usize>>,
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
        let component = components[id.0].as_ref().expect("component should exist");
        let Some(program) = component.program.as_ref() else {
            continue;
        };

        for (lowered_mount_index, mount) in program.mounts().iter().enumerate() {
            let source_mount_index =
                authored_mount_index(mount_source_indices_by_component, id, lowered_mount_index);
            match mount {
                ProgramMount::Slot {
                    slot: slot_name, ..
                } => {
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
                        let (src, span) =
                            mount_source_site(provenance, store, id, source_mount_index)
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
                        let (src, span) =
                            mount_source_site(provenance, store, id, source_mount_index)
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
                        let (src, span) =
                            mount_source_site(provenance, store, id, source_mount_index)
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
                ProgramMount::Resource {
                    resource: resource_name,
                    ..
                } => {
                    sinks_by_resource
                        .entry(ResourceRef {
                            component: id,
                            name: resource_name.clone(),
                        })
                        .or_default()
                        .push(StorageMountSink {
                            component: id,
                            sink_id: format!("mount:{lowered_mount_index}"),
                            description: format!("resources.{resource_name}"),
                            site: StorageMountSinkSite::Mount {
                                component: id,
                                authored_mount_index: source_mount_index,
                            },
                        });
                }
                ProgramMount::File(_) | ProgramMount::Framework { .. } => {}
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
