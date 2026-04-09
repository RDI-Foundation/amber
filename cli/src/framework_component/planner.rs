use super::{api::*, state::*, *};

pub(super) async fn prepare_child_record(
    state: &mut FrameworkControlState,
    authority_realm_id: usize,
    request: &CreateChildRequest,
) -> std::result::Result<LiveChildRecord, ProtocolErrorResponse> {
    validate_child_name(&request.name)?;
    let authority_realm = ComponentId(authority_realm_id);
    let template = decode_live_scenario(state)?
        .component(authority_realm)
        .child_templates
        .get(request.template.as_str())
        .ok_or_else(|| {
            protocol_error(ProtocolErrorCode::UnknownTemplate, "unknown child template")
        })?
        .clone();
    validate_child_name_available(state, authority_realm_id, &request.name)?;
    validate_template_limits(
        state,
        authority_realm_id,
        request.template.as_str(),
        &request.name,
        &template,
    )?;
    let selected_manifest_catalog_key =
        select_manifest_catalog_key(state, &template, request).await?;
    let current_live_scenario_ir = live_scenario_ir(state)?;
    let live_scenario = decode_live_scenario(state)?;
    let authority_component = live_scenario.component(authority_realm);
    let bindable_sources = bindable_source_candidates(
        &live_scenario,
        &current_live_scenario_ir,
        state,
        authority_realm,
    )?;
    let contract = resolve_template_contract(
        &state.base_scenario.manifest_catalog,
        &template,
        &selected_manifest_catalog_key,
    )?;
    let rendered_config = build_child_config(&contract, request)?;
    let resolved_bindings = resolve_template_bindings(&contract, request, &bindable_sources)?;
    let child_id = allocate_child_id(state);
    let (wrapper_manifest, synthetic_sources) = build_wrapper_manifest(
        state,
        &contract,
        &request.name,
        &selected_manifest_catalog_key,
        rendered_config,
        &resolved_bindings,
    )?;
    let wrapper_url = wrapper_manifest_url(authority_realm_id, child_id);
    let compiled = compile_frozen_manifest(
        state,
        ManifestRef::from_url(wrapper_url.clone()),
        BTreeMap::from([(wrapper_url.to_string(), wrapper_manifest)]),
    )
    .await?;
    let (fragment, outputs) = extract_live_child_fragment(
        state,
        &compiled,
        &synthetic_sources,
        authority_component,
        &request.name,
        child_id,
    )?;

    let mut child = LiveChildRecord {
        child_id,
        authority_realm_id,
        name: request.name.clone(),
        state: ChildState::CreatePrepared,
        template_name: Some(request.template.clone()),
        selected_manifest_catalog_key: Some(selected_manifest_catalog_key),
        fragment: Some(fragment),
        input_bindings: child_input_binding_records(&live_scenario, &resolved_bindings),
        assignments: BTreeMap::new(),
        site_plans: Vec::new(),
        overlay_ids: Vec::new(),
        overlays: Vec::new(),
        outputs,
    };

    let fragment = child.fragment.as_ref().expect("fragment set");
    let combined_scenario = scenario_with_fragment(&current_live_scenario_ir, fragment)?;
    rebuild_live_child_runtime_metadata(
        state,
        &combined_scenario,
        &live_assignment_map(state),
        &mut child,
    )?;
    Ok(child)
}

pub(super) fn rebuild_live_child_runtime_metadata(
    state: &FrameworkControlState,
    scenario: &Scenario,
    existing_assignments: &BTreeMap<String, String>,
    child: &mut LiveChildRecord,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let fragment = child.fragment.as_ref().ok_or_else(|| {
        protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &format!(
                "dynamic child `{}` is missing its authoritative live fragment",
                child.name
            ),
        )
    })?;
    let fragment_component_ids = fragment
        .components
        .iter()
        .map(|component| ComponentId(component.id))
        .collect::<BTreeSet<_>>();
    let planned = plan_dynamic_fragment(
        scenario,
        &fragment_component_ids,
        &placement_file_from_state(state),
        &run_plan_activation_from_state(state),
        existing_assignments,
    )
    .map_err(|err| {
        protocol_error(
            ProtocolErrorCode::PlacementUnsatisfied,
            &format!("child placement could not be satisfied: {err}"),
        )
    })?;
    child.assignments = planned.assignments;
    child.overlays = dynamic_overlay_records(&planned.incident_links, fragment);
    let mut live_assignments = existing_assignments.clone();
    live_assignments.extend(child.assignments.clone());
    child.site_plans = dynamic_site_plans(
        &planned.site_plans,
        &child.assignments,
        fragment,
        &child.outputs,
        &child.overlays,
        &dynamic_input_route_records(&live_assignments, fragment, &child.input_bindings),
    )?;
    child.overlay_ids = child
        .overlays
        .iter()
        .map(|overlay| overlay.overlay_id.clone())
        .collect();
    Ok(())
}

pub(super) fn remove_incident_bindings_from_survivors(
    state: &mut FrameworkControlState,
    child_id: u64,
) {
    for live_child in &mut state.live_children {
        if live_child.child_id == child_id {
            continue;
        }
        let Some(fragment) = live_child.fragment.as_mut() else {
            continue;
        };
        fragment
            .bindings
            .retain(|binding| binding.source_child_id != Some(child_id));
    }
    for pending in &mut state.pending_creates {
        if pending.child.child_id == child_id {
            continue;
        }
        let Some(fragment) = pending.child.fragment.as_mut() else {
            continue;
        };
        fragment
            .bindings
            .retain(|binding| binding.source_child_id != Some(child_id));
    }
    for pending in &mut state.pending_destroys {
        if pending.child.child_id == child_id {
            continue;
        }
        let Some(fragment) = pending.child.fragment.as_mut() else {
            continue;
        };
        fragment
            .bindings
            .retain(|binding| binding.source_child_id != Some(child_id));
    }
}

#[cfg(test)]
pub(super) async fn create_child(
    state: &mut FrameworkControlState,
    authority_realm_id: usize,
    request: CreateChildRequest,
    state_path: &Path,
) -> std::result::Result<CreateChildResponse, ProtocolErrorResponse> {
    let child = prepare_child_record(state, authority_realm_id, &request).await?;
    let tx_id = allocate_tx_id(state);
    persist_control_state_update(state, state_path, "create_prepared", |state| {
        state.pending_creates.push(PendingCreateRecord {
            tx_id,
            child: child.clone(),
        });
        append_journal_entry(state, tx_id, &child, ChildState::CreateRequested);
        append_journal_entry(state, tx_id, &child, ChildState::CreatePrepared);
        Ok(())
    })?;

    persist_control_state_update(state, state_path, "create_committed_hidden", |state| {
        transition_child_state(state, child.child_id, ChildState::CreateCommittedHidden)?;
        append_journal_entry(state, tx_id, &child, ChildState::CreateCommittedHidden);
        Ok(())
    })?;

    persist_control_state_update(state, state_path, "create_live", |state| {
        append_journal_entry(state, tx_id, &child, ChildState::Live);
        move_pending_create_to_live(state, child.child_id)?;
        Ok(())
    })?;

    let live_child = state
        .live_children
        .iter()
        .find(|candidate| candidate.child_id == child.child_id)
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                "created child disappeared from control state",
            )
        })?;
    Ok(create_child_response(live_child))
}

#[cfg(test)]
pub(super) async fn destroy_child(
    state: &mut FrameworkControlState,
    authority_realm_id: usize,
    child_name: &str,
    state_path: &Path,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let Some(child_index) = state.live_children.iter().position(|child| {
        child.authority_realm_id == authority_realm_id
            && child.name == child_name
            && child.state == ChildState::Live
    }) else {
        return Ok(());
    };
    let child_id = state.live_children[child_index].child_id;
    let child = state.live_children[child_index].clone();
    let tx_id = allocate_tx_id(state);

    persist_control_state_update(state, state_path, "destroy_requested", |state| {
        append_journal_entry(state, tx_id, &child, ChildState::DestroyRequested);
        move_live_child_to_pending_destroy(state, child_id, tx_id)?;
        Ok(())
    })?;

    persist_control_state_update(state, state_path, "destroy_retracted", |state| {
        remove_incident_bindings_from_survivors(state, child_id);
        transition_child_state(state, child_id, ChildState::DestroyRetracted)?;
        append_journal_entry(state, tx_id, &child, ChildState::DestroyRetracted);
        Ok(())
    })?;

    persist_control_state_update(state, state_path, "destroy_committed", |state| {
        append_journal_entry(state, tx_id, &child, ChildState::DestroyCommitted);
        remove_pending_destroy(state, child_id)?;
        Ok(())
    })?;
    Ok(())
}

pub(super) fn child_is_visible(child: &LiveChildRecord) -> bool {
    matches!(child.state, ChildState::Live | ChildState::DestroyRequested)
}

pub(super) fn child_counts_toward_template_limits(child: &LiveChildRecord) -> bool {
    !matches!(
        child.state,
        ChildState::CreateAborted | ChildState::DestroyCommitted
    )
}

pub(super) fn validate_child_name(name: &str) -> std::result::Result<(), ProtocolErrorResponse> {
    if name.trim().is_empty() {
        return Err(protocol_error(
            ProtocolErrorCode::InvalidConfig,
            "child name must not be empty",
        ));
    }
    if name.contains('.') {
        return Err(protocol_error(
            ProtocolErrorCode::InvalidConfig,
            "child name must not contain `.`",
        ));
    }
    Ok(())
}

pub(super) fn validate_child_name_available(
    state: &FrameworkControlState,
    authority_realm_id: usize,
    child_name: &str,
) -> std::result::Result<(), ProtocolErrorResponse> {
    if all_child_records(state).any(|child| {
        child.authority_realm_id == authority_realm_id
            && child.name == child_name
            && child.state != ChildState::CreateAborted
            && child.state != ChildState::DestroyCommitted
    }) {
        return Err(protocol_error(
            ProtocolErrorCode::NameConflict,
            &format!("child `{child_name}` already exists"),
        ));
    }
    Ok(())
}

pub(super) fn validate_template_limits(
    state: &FrameworkControlState,
    authority_realm_id: usize,
    template_name: &str,
    child_name: &str,
    template: &ChildTemplate,
) -> std::result::Result<(), ProtocolErrorResponse> {
    if let Some(limit) = template
        .limits
        .as_ref()
        .and_then(|limits| limits.max_live_children)
    {
        let live = state
            .live_children
            .iter()
            .chain(state.pending_creates.iter().map(|record| &record.child))
            .chain(state.pending_destroys.iter().map(|record| &record.child))
            .filter(|child| child.authority_realm_id == authority_realm_id)
            .filter(|child| child.template_name.as_deref() == Some(template_name))
            .filter(|child| child_counts_toward_template_limits(child))
            .count() as u32;
        if live >= limit {
            return Err(protocol_error(
                ProtocolErrorCode::NameConflict,
                &format!(
                    "template `{template_name}` already has the maximum of {limit} live children"
                ),
            ));
        }
    }
    if let Some(pattern) = template
        .limits
        .as_ref()
        .and_then(|limits| limits.name_pattern.as_deref())
    {
        let regex = regex::Regex::new(pattern).map_err(|err| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &format!("invalid child template name_pattern `{pattern}`: {err}"),
            )
        })?;
        if !regex.is_match(child_name) {
            return Err(protocol_error(
                ProtocolErrorCode::InvalidConfig,
                &format!("child name `{child_name}` does not match `{pattern}`"),
            ));
        }
    }
    Ok(())
}

#[derive(Clone)]
pub(super) struct ResolvedTemplateContract {
    pub(super) config: BTreeMap<String, TemplateConfigField>,
    pub(super) bindings: BTreeMap<String, TemplateBinding>,
    pub(super) slot_decls: BTreeMap<String, SlotDecl>,
    pub(super) visible_exports: Vec<String>,
}

fn runtime_manifest_ref(
    manifest: &ManifestRef,
) -> std::result::Result<ManifestRef, ProtocolErrorResponse> {
    if manifest.url.is_relative() {
        return Err(protocol_error(
            ProtocolErrorCode::InvalidManifestRef,
            "runtime child manifest refs must use absolute URLs",
        ));
    }
    Ok(manifest.clone())
}

pub(super) async fn select_manifest_catalog_key(
    state: &mut FrameworkControlState,
    template: &ChildTemplate,
    request: &CreateChildRequest,
) -> std::result::Result<String, ProtocolErrorResponse> {
    match template.manifests.as_ref() {
        Some(keys) if keys.len() == 1 => {
            if request.manifest.is_some() {
                return Err(protocol_error(
                    ProtocolErrorCode::ManifestNotAllowed,
                    "exact child templates must not specify `manifest` in CreateChild",
                ));
            }
            Ok(keys[0].clone())
        }
        Some(keys) => {
            let selected = runtime_manifest_ref(request.manifest.as_ref().ok_or_else(|| {
                protocol_error(
                    ProtocolErrorCode::ManifestRequired,
                    "bounded child templates must specify `manifest` in CreateChild",
                )
            })?)?;
            let selected_url = selected
                .url
                .as_url()
                .expect("validated runtime manifest refs are absolute")
                .as_str();
            for key in keys {
                let entry = state
                    .base_scenario
                    .manifest_catalog
                    .get(key)
                    .ok_or_else(|| {
                        protocol_error(
                            ProtocolErrorCode::ControlStateUnavailable,
                            &format!("frozen manifest catalog entry `{key}` is missing"),
                        )
                    })?;
                if entry.source_ref != selected_url {
                    continue;
                }
                if let Some(digest) = selected.digest
                    && digest != entry.digest
                {
                    return Err(protocol_error(
                        ProtocolErrorCode::ManifestDigestMismatch,
                        &format!(
                            "manifest `{selected_url}` digest does not match the bounded template"
                        ),
                    ));
                }
                return Ok(key.clone());
            }
            Err(protocol_error(
                ProtocolErrorCode::ManifestNotAllowed,
                &format!(
                    "manifest `{selected_url}` is not allowed for template `{}`",
                    request.template
                ),
            ))
        }
        None => {
            let selected = runtime_manifest_ref(request.manifest.as_ref().ok_or_else(|| {
                protocol_error(
                    ProtocolErrorCode::ManifestRequired,
                    "open child templates must specify `manifest` in CreateChild",
                )
            })?)?;
            let selected_url = selected
                .url
                .as_url()
                .expect("validated runtime manifest refs are absolute")
                .to_string();
            if let Some(entry) = state.base_scenario.manifest_catalog.get(&selected_url) {
                if let Some(digest) = selected.digest
                    && digest != entry.digest
                {
                    return Err(protocol_error(
                        ProtocolErrorCode::ManifestDigestMismatch,
                        &format!(
                            "manifest `{selected_url}` digest does not match the admitted manifest"
                        ),
                    ));
                }
                admit_runtime_manifest_dependencies(state, &selected_url).await?;
                return Ok(selected_url);
            }
            admit_runtime_manifest(state, &selected).await
        }
    }
}

async fn admit_runtime_manifest(
    state: &mut FrameworkControlState,
    manifest: &ManifestRef,
) -> std::result::Result<String, ProtocolErrorResponse> {
    let resolver = Resolver::new();
    let mut pending = vec![manifest.clone()];
    let mut root_key = None;

    while let Some(current) = pending.pop() {
        let requested_url = current
            .url
            .as_url()
            .expect("validated runtime manifest refs are absolute")
            .clone();
        let resolution = resolver
            .resolve(&requested_url, current.digest)
            .await
            .map_err(|err| match err {
                amber_resolver::Error::MismatchedDigest(_) => protocol_error(
                    ProtocolErrorCode::ManifestDigestMismatch,
                    &format!("manifest `{requested_url}` digest mismatch"),
                ),
                other => protocol_error(
                    ProtocolErrorCode::ManifestResolutionFailed,
                    &format!("failed to resolve manifest `{requested_url}`: {other}"),
                ),
            })?;
        let key = resolution.url.to_string();
        if root_key.is_none() {
            root_key = Some(key.clone());
        }
        if state.base_scenario.manifest_catalog.contains_key(&key) {
            continue;
        }

        let dependencies = runtime_manifest_dependencies(&resolution.manifest, &resolution.url)?;
        let digest = resolution.manifest.digest();
        state.base_scenario.manifest_catalog.insert(
            key.clone(),
            ManifestCatalogEntryIr {
                source_ref: key.clone(),
                digest,
                manifest: resolution.manifest,
            },
        );
        pending.extend(dependencies);
    }

    Ok(root_key.expect("root runtime manifest should always resolve"))
}

async fn admit_runtime_manifest_dependencies(
    state: &mut FrameworkControlState,
    root_key: &str,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let mut pending = vec![root_key.to_string()];
    let mut visited = BTreeSet::new();

    while let Some(key) = pending.pop() {
        if !visited.insert(key.clone()) {
            continue;
        }

        let (source_ref, manifest) = {
            let entry = state
                .base_scenario
                .manifest_catalog
                .get(&key)
                .ok_or_else(|| {
                    protocol_error(
                        ProtocolErrorCode::ControlStateUnavailable,
                        &format!("frozen manifest catalog entry `{key}` is missing"),
                    )
                })?;
            (entry.source_ref.clone(), entry.manifest.clone())
        };
        let base_url = url::Url::parse(&source_ref).map_err(|err| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &format!("invalid frozen manifest catalog source_ref `{source_ref}`: {err}"),
            )
        })?;

        for dependency in runtime_manifest_dependencies(&manifest, &base_url)? {
            let dependency_key = dependency
                .url
                .as_url()
                .expect("resolved runtime manifest dependencies are absolute")
                .to_string();
            if let Some(entry) = state.base_scenario.manifest_catalog.get(&dependency_key) {
                if let Some(digest) = dependency.digest
                    && digest != entry.digest
                {
                    return Err(protocol_error(
                        ProtocolErrorCode::ManifestDigestMismatch,
                        &format!(
                            "manifest `{dependency_key}` digest does not match the admitted \
                             manifest"
                        ),
                    ));
                }
                pending.push(dependency_key);
                continue;
            }

            pending.push(admit_runtime_manifest(state, &dependency).await?);
        }
    }

    Ok(())
}

fn runtime_manifest_dependencies(
    manifest: &Manifest,
    base_url: &url::Url,
) -> std::result::Result<Vec<ManifestRef>, ProtocolErrorResponse> {
    let component_refs = manifest
        .components()
        .values()
        .map(|component| match component {
            ComponentDecl::Reference(reference) => reference,
            ComponentDecl::Object(component) => &component.manifest,
            _ => unreachable!("manifest component declarations only carry manifest references"),
        });
    let template_refs = manifest.child_templates().values().flat_map(|template| {
        template
            .manifest
            .as_ref()
            .into_iter()
            .flat_map(|manifest| match manifest {
                amber_manifest::ChildTemplateManifestDecl::One(reference) => {
                    std::slice::from_ref(reference).iter()
                }
                amber_manifest::ChildTemplateManifestDecl::Many(references) => references.iter(),
                _ => unreachable!("child template manifests are normalized to manifest refs"),
            })
    });

    component_refs
        .chain(template_refs)
        .map(|reference| {
            let resolved_url = reference.url.resolve(base_url).map_err(|err| {
                protocol_error(
                    ProtocolErrorCode::ManifestResolutionFailed,
                    &format!(
                        "failed to resolve manifest `{}` relative to `{base_url}`: {err}",
                        reference.url.as_str()
                    ),
                )
            })?;
            Ok(ManifestRef::new(resolved_url, reference.digest))
        })
        .collect()
}

pub(super) fn manifest_catalog_closure<I>(
    manifest_catalog: &BTreeMap<String, ManifestCatalogEntryIr>,
    roots: I,
) -> std::result::Result<BTreeSet<String>, ProtocolErrorResponse>
where
    I: IntoIterator<Item = String>,
{
    let mut required = BTreeSet::new();
    let mut pending = roots.into_iter().collect::<Vec<_>>();

    while let Some(key) = pending.pop() {
        if !required.insert(key.clone()) {
            continue;
        }

        let entry = manifest_catalog.get(&key).ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &format!("frozen manifest catalog entry `{key}` is missing"),
            )
        })?;
        let base_url = url::Url::parse(&entry.source_ref).map_err(|err| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &format!(
                    "invalid frozen manifest catalog source_ref `{}` for `{key}`: {err}",
                    entry.source_ref
                ),
            )
        })?;
        pending.extend(
            runtime_manifest_dependencies(&entry.manifest, &base_url)?
                .into_iter()
                .map(|reference| {
                    reference
                        .url
                        .as_url()
                        .expect("resolved runtime manifest dependencies are absolute")
                        .to_string()
                }),
        );
    }

    Ok(required)
}

pub(super) fn resolve_template_contract(
    manifest_catalog: &BTreeMap<String, ManifestCatalogEntryIr>,
    template: &ChildTemplate,
    selected_manifest_catalog_key: &str,
) -> std::result::Result<ResolvedTemplateContract, ProtocolErrorResponse> {
    let manifest = manifest_catalog
        .get(selected_manifest_catalog_key)
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &format!(
                    "frozen manifest catalog entry `{selected_manifest_catalog_key}` is missing"
                ),
            )
        })?
        .manifest
        .clone();

    Ok(ResolvedTemplateContract {
        config: resolve_template_config_fields(template, &manifest, selected_manifest_catalog_key)?,
        bindings: resolve_template_binding_fields(
            template,
            &manifest,
            selected_manifest_catalog_key,
        )?,
        slot_decls: manifest
            .slots()
            .iter()
            .map(|(name, decl)| (name.to_string(), decl.clone()))
            .collect(),
        visible_exports: resolve_template_visible_exports(
            template,
            &manifest,
            selected_manifest_catalog_key,
        )?,
    })
}

fn resolve_template_config_fields(
    template: &ChildTemplate,
    manifest: &Manifest,
    selected_manifest_catalog_key: &str,
) -> std::result::Result<BTreeMap<String, TemplateConfigField>, ProtocolErrorResponse> {
    let Some(schema) = manifest.config_schema() else {
        if let Some(name) = template.config.keys().next() {
            return Err(protocol_error(
                ProtocolErrorCode::InvalidConfig,
                &format!(
                    "template prefills config field `{name}`, but manifest \
                     `{selected_manifest_catalog_key}` does not declare config"
                ),
            ));
        }
        return Ok(BTreeMap::new());
    };

    let properties = schema
        .0
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .into_iter()
        .flatten()
        .collect::<BTreeMap<_, _>>();
    for name in template.config.keys() {
        if !properties.contains_key(name) {
            return Err(protocol_error(
                ProtocolErrorCode::InvalidConfig,
                &format!(
                    "template prefills config field `{name}`, but manifest \
                     `{selected_manifest_catalog_key}` does not declare it"
                ),
            ));
        }
    }

    let required = schema
        .0
        .get("required")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .collect::<BTreeSet<_>>();
    Ok(properties
        .keys()
        .map(|name| {
            let field = template
                .config
                .get(*name)
                .map(|field| match field {
                    TemplateConfigField::Prefilled { value } => TemplateConfigField::Prefilled {
                        value: value.clone(),
                    },
                    TemplateConfigField::Open { .. } => {
                        panic!("stored child templates must not persist open config fields")
                    }
                })
                .unwrap_or(TemplateConfigField::Open {
                    required: required.contains(name.as_str()),
                });
            ((*name).clone(), field)
        })
        .collect())
}

fn resolve_template_binding_fields(
    template: &ChildTemplate,
    manifest: &Manifest,
    selected_manifest_catalog_key: &str,
) -> std::result::Result<BTreeMap<String, TemplateBinding>, ProtocolErrorResponse> {
    for slot_name in template.bindings.keys() {
        if !manifest.slots().contains_key(slot_name.as_str()) {
            return Err(protocol_error(
                ProtocolErrorCode::InvalidBinding,
                &format!(
                    "template prefills binding `{slot_name}`, but manifest \
                     `{selected_manifest_catalog_key}` does not declare that slot"
                ),
            ));
        }
    }

    Ok(manifest
        .slots()
        .iter()
        .map(|(slot_name, slot_decl)| {
            let binding = template
                .bindings
                .get(slot_name.as_str())
                .map(|binding| match binding {
                    TemplateBinding::Prefilled { selector } => TemplateBinding::Prefilled {
                        selector: selector.clone(),
                    },
                    TemplateBinding::Open { .. } => {
                        panic!("stored child templates must not persist open bindings")
                    }
                })
                .unwrap_or(TemplateBinding::Open {
                    optional: slot_decl.optional,
                });
            (slot_name.to_string(), binding)
        })
        .collect())
}

fn resolve_template_visible_exports(
    template: &ChildTemplate,
    manifest: &Manifest,
    selected_manifest_catalog_key: &str,
) -> std::result::Result<Vec<String>, ProtocolErrorResponse> {
    if let Some(visible_exports) = template.visible_exports.as_ref() {
        for export_name in visible_exports {
            if !manifest.exports().contains_key(export_name.as_str()) {
                return Err(protocol_error(
                    ProtocolErrorCode::InvalidConfig,
                    &format!(
                        "template exposes export `{export_name}`, but manifest \
                         `{selected_manifest_catalog_key}` does not declare it"
                    ),
                ));
            }
        }
        return Ok(visible_exports.clone());
    }
    Ok(manifest.exports().keys().map(ToString::to_string).collect())
}

pub(super) fn build_child_config(
    contract: &ResolvedTemplateContract,
    request: &CreateChildRequest,
) -> std::result::Result<Option<serde_json::Value>, ProtocolErrorResponse> {
    for key in request.config.keys() {
        if !contract.config.contains_key(key.as_str()) {
            return Err(protocol_error(
                ProtocolErrorCode::InvalidConfig,
                &format!("unknown child config field `{key}`"),
            ));
        }
    }

    let mut config = serde_json::Map::new();
    for (name, field) in &contract.config {
        match field {
            TemplateConfigField::Prefilled { value } => {
                if request.config.contains_key(name.as_str()) {
                    return Err(protocol_error(
                        ProtocolErrorCode::InvalidConfig,
                        &format!("config field `{name}` is prefilled by the template"),
                    ));
                }
                config.insert(name.clone(), value.clone());
            }
            TemplateConfigField::Open { required } => {
                if let Some(value) = request.config.get(name.as_str()) {
                    config.insert(name.clone(), value.clone());
                } else if *required {
                    return Err(protocol_error(
                        ProtocolErrorCode::InvalidConfig,
                        &format!("missing required config field `{name}`"),
                    ));
                }
            }
        }
    }

    Ok((!config.is_empty()).then_some(serde_json::Value::Object(config)))
}

pub(super) fn resolve_template_bindings(
    contract: &ResolvedTemplateContract,
    request: &CreateChildRequest,
    bindable_sources: &[BindableSourceCandidate],
) -> std::result::Result<Vec<ResolvedTemplateBinding>, ProtocolErrorResponse> {
    for key in request.bindings.keys() {
        if !contract.bindings.contains_key(key.as_str()) {
            return Err(protocol_error(
                ProtocolErrorCode::InvalidBinding,
                &format!("unknown child binding field `{key}`"),
            ));
        }
    }

    contract
        .bindings
        .iter()
        .map(|(slot_name, field)| {
            let slot_decl = contract
                .slot_decls
                .get(slot_name.as_str())
                .ok_or_else(|| {
                    protocol_error(
                        ProtocolErrorCode::ControlStateUnavailable,
                        &format!("resolved template contract is missing slot `{slot_name}`"),
                    )
                })?
                .clone();
            let candidate = match field {
                TemplateBinding::Prefilled { selector } => {
                    Some(find_bindable_source(bindable_sources, selector.as_str())?)
                }
                TemplateBinding::Open { optional } => {
                    let Some(input) = request.bindings.get(slot_name.as_str()) else {
                        if *optional {
                            return Ok(None);
                        }
                        return Err(protocol_error(
                            ProtocolErrorCode::InvalidBinding,
                            &format!("missing required binding `{slot_name}`"),
                        ));
                    };
                    let selected = match (&input.selector, &input.handle) {
                        (Some(selector), None) => find_bindable_source(bindable_sources, selector)?,
                        (None, Some(handle)) => {
                            find_bindable_source_by_handle(bindable_sources, handle)?
                        }
                        _ => {
                            return Err(protocol_error(
                                ProtocolErrorCode::InvalidBinding,
                                &format!(
                                    "binding `{slot_name}` must specify exactly one of `selector` \
                                     or `handle`"
                                ),
                            ));
                        }
                    };
                    Some(selected)
                }
            };
            if let Some(selected) = candidate.as_ref()
                && !source_compatible(slot_decl.decl.clone(), selected.decl.clone())
            {
                return Err(protocol_error(
                    ProtocolErrorCode::BindingTypeMismatch,
                    &format!(
                        "binding `{slot_name}` expects `{}` but `{}` provides `{}`",
                        slot_decl.decl.kind, selected.selector, selected.decl.kind
                    ),
                ));
            }

            Ok(candidate.map(|candidate| ResolvedTemplateBinding {
                slot_name: slot_name.clone(),
                slot_decl,
                sources: candidate.sources.clone(),
                source_child_id: candidate.source_child_id,
            }))
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .map(|bindings| bindings.into_iter().flatten().collect())
}

pub(super) fn build_wrapper_manifest(
    state: &FrameworkControlState,
    contract: &ResolvedTemplateContract,
    child_name: &str,
    selected_manifest_catalog_key: &str,
    rendered_config: Option<serde_json::Value>,
    resolved_bindings: &[ResolvedTemplateBinding],
) -> std::result::Result<(Manifest, BTreeMap<String, SyntheticSourceRecord>), ProtocolErrorResponse>
{
    let entry = state
        .base_scenario
        .manifest_catalog
        .get(selected_manifest_catalog_key)
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &format!(
                    "frozen manifest catalog entry `{selected_manifest_catalog_key}` is missing"
                ),
            )
        })?;
    let child_url = url::Url::parse(&entry.source_ref).map_err(|err| {
        protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &format!(
                "invalid frozen manifest catalog source_ref `{selected_manifest_catalog_key}`: \
                 {err}"
            ),
        )
    })?;

    let mut slots = BTreeMap::new();
    let mut bindings = Vec::new();
    let mut synthetic_sources = BTreeMap::new();
    let mut next_synthetic = 0usize;

    for binding in resolved_bindings {
        for source in &binding.sources {
            let synthetic_name = format!("__amber_src_{next_synthetic}");
            next_synthetic += 1;
            let (actual_source, source_child_id) = match &source.from {
                BindingFrom::Component(provide) => (
                    BindingFrom::Component(provide.clone()),
                    binding
                        .source_child_id
                        .or_else(|| live_child_component_owner(state, provide.component.0)),
                ),
                BindingFrom::Resource(resource) => (
                    BindingFrom::Resource(resource.clone()),
                    binding.source_child_id,
                ),
                BindingFrom::Framework(framework) => (
                    BindingFrom::Framework(framework.clone()),
                    binding.source_child_id,
                ),
                BindingFrom::External(slot) => {
                    (BindingFrom::External(slot.clone()), binding.source_child_id)
                }
            };
            synthetic_sources.insert(
                synthetic_name.clone(),
                SyntheticSourceRecord {
                    slot_name: binding.slot_name.clone(),
                    actual_source,
                    source_child_id,
                    weak: source.weak,
                },
            );

            if let BindingFrom::Framework(framework) = &source.from {
                bindings.push(raw_binding(
                    &format!("#{child_name}"),
                    binding.slot_name.clone(),
                    "framework",
                    framework.capability.to_string(),
                    source.weak,
                )?);
                continue;
            }

            slots.insert(
                synthetic_name.clone(),
                SlotDecl::builder()
                    .decl(binding.slot_decl.decl.clone())
                    .optional(false)
                    .multiple(false)
                    .build(),
            );
            bindings.push(raw_binding(
                &format!("#{child_name}"),
                binding.slot_name.clone(),
                "slots",
                synthetic_name,
                true,
            )?);
        }
    }

    let exports = contract
        .visible_exports
        .iter()
        .cloned()
        .map(|export_name| {
            let target = format!("#{child_name}.{export_name}")
                .parse::<RawExportTarget>()
                .map_err(|err| {
                    protocol_error(
                        ProtocolErrorCode::ControlStateUnavailable,
                        &format!("failed to build synthetic export target: {err}"),
                    )
                })?;
            Ok((export_name, target))
        })
        .collect::<std::result::Result<BTreeMap<_, _>, _>>()?;

    let manifest = Manifest::builder()
        .components(BTreeMap::from([(
            child_name.to_string(),
            ComponentDecl::Object(component_ref_from_url(
                ManifestRef::from_url(child_url),
                rendered_config,
            )?),
        )]))
        .slots(slots)
        .bindings(bindings)
        .exports(exports)
        .build()
        .map_err(|err| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &format!("failed to build synthetic wrapper manifest: {err}"),
            )
        })?;

    Ok((manifest, synthetic_sources))
}

pub(super) fn raw_binding(
    to: &str,
    slot: String,
    from: &str,
    capability: String,
    weak: bool,
) -> std::result::Result<RawBinding, ProtocolErrorResponse> {
    serde_json::from_value(json!({
        "to": to,
        "slot": slot,
        "from": from,
        "capability": capability,
        "weak": weak,
    }))
    .map_err(|err| {
        protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &format!("failed to build synthetic binding: {err}"),
        )
    })
}

pub(super) fn component_ref_from_url(
    manifest: ManifestRef,
    config: Option<serde_json::Value>,
) -> std::result::Result<ComponentRef, ProtocolErrorResponse> {
    let mut value = json!({ "manifest": manifest });
    if let Some(config) = config
        && let Some(object) = value.as_object_mut()
    {
        object.insert("config".to_string(), config);
    }
    serde_json::from_value(value).map_err(|err| {
        protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &format!("failed to build synthetic child component ref: {err}"),
        )
    })
}

pub(super) fn wrapper_manifest_url(authority_realm_id: usize, child_id: u64) -> url::Url {
    url::Url::parse(&format!(
        "amber+framework://rendered-child/{authority_realm_id}/{child_id}"
    ))
    .expect("synthetic wrapper URL should parse")
}

pub(super) fn allocate_child_id(state: &mut FrameworkControlState) -> u64 {
    state.next_child_id += 1;
    state.next_child_id
}

pub(super) fn allocate_tx_id(state: &mut FrameworkControlState) -> u64 {
    state.next_tx_id += 1;
    state.next_tx_id
}

pub(super) fn append_journal_entry(
    state: &mut FrameworkControlState,
    tx_id: u64,
    child: &LiveChildRecord,
    child_state: ChildState,
) {
    state.generation += 1;
    state.journal.push(ControlJournalEntry {
        tx_id,
        child_id: child.child_id,
        authority_realm_id: child.authority_realm_id,
        child_name: child.name.clone(),
        state: child_state,
        generation: state.generation,
    });
}

pub(super) fn transition_child_state(
    state: &mut FrameworkControlState,
    child_id: u64,
    next_state: ChildState,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let child = child_record_mut(state, child_id)?;
    child.state = next_state;
    Ok(())
}

pub(super) fn move_pending_create_to_live(
    state: &mut FrameworkControlState,
    child_id: u64,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let index = state
        .pending_creates
        .iter()
        .position(|record| record.child.child_id == child_id)
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &format!("child id {child_id} is missing pending create state"),
            )
        })?;
    let mut record = state.pending_creates.remove(index);
    record.child.state = ChildState::Live;
    state.live_children.push(record.child);
    Ok(())
}

pub(super) fn remove_pending_create(
    state: &mut FrameworkControlState,
    child_id: u64,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let index = state
        .pending_creates
        .iter()
        .position(|record| record.child.child_id == child_id)
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &format!("child id {child_id} is missing pending create state"),
            )
        })?;
    state.pending_creates.remove(index);
    Ok(())
}

pub(super) fn move_live_child_to_pending_destroy(
    state: &mut FrameworkControlState,
    child_id: u64,
    tx_id: u64,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let index = state
        .live_children
        .iter()
        .position(|child| child.child_id == child_id)
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &format!("child id {child_id} is missing live child state"),
            )
        })?;
    let mut child = state.live_children.remove(index);
    child.state = ChildState::DestroyRequested;
    state
        .pending_destroys
        .push(PendingDestroyRecord { tx_id, child });
    Ok(())
}

pub(super) fn remove_pending_destroy(
    state: &mut FrameworkControlState,
    child_id: u64,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let index = state
        .pending_destroys
        .iter()
        .position(|record| record.child.child_id == child_id)
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &format!("child id {child_id} is missing pending destroy state"),
            )
        })?;
    state.pending_destroys.remove(index);
    Ok(())
}

pub(super) fn remove_child_record(
    state: &mut FrameworkControlState,
    child_id: u64,
) -> std::result::Result<(), ProtocolErrorResponse> {
    match child_record_location(state, child_id)? {
        ChildRecordLocation::Live(index) => {
            state.live_children.remove(index);
        }
        ChildRecordLocation::PendingCreate(index) => {
            state.pending_creates.remove(index);
        }
        ChildRecordLocation::PendingDestroy(index) => {
            state.pending_destroys.remove(index);
        }
    }
    Ok(())
}

pub(super) fn dynamic_site_plans(
    desired_site_plans: &BTreeMap<String, amber_compiler::run_plan::RunSitePlan>,
    assignments: &BTreeMap<String, String>,
    fragment: &LiveScenarioFragment,
    outputs: &BTreeMap<String, OutputHandleRecord>,
    overlays: &[DynamicOverlayRecord],
    routed_inputs: &[DynamicInputRouteRecord],
) -> std::result::Result<Vec<DynamicSitePlanRecord>, ProtocolErrorResponse> {
    let child_moniker_set = fragment
        .components
        .iter()
        .map(|component| component.moniker.as_str())
        .collect::<BTreeSet<_>>();
    let child_monikers = fragment
        .components
        .iter()
        .map(|component| (component.id, component.moniker.as_str()))
        .collect::<BTreeMap<_, _>>();
    let mut site_plans = Vec::new();
    for (site_id, desired_site_plan) in desired_site_plans {
        let component_ids = desired_site_plan
            .scenario_ir
            .components
            .iter()
            .filter(|component| child_moniker_set.contains(component.moniker.as_str()))
            .map(|component| component.id)
            .collect::<Vec<_>>();
        if component_ids.is_empty() {
            continue;
        }
        let assigned_components = desired_site_plan
            .assigned_components
            .iter()
            .filter(|moniker| {
                fragment
                    .components
                    .iter()
                    .any(|component| component.moniker == **moniker)
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut proxy_exports = BTreeMap::new();
        for (name, output) in outputs {
            let Some((component_id, component_moniker, provide_name)) =
                output.sources.iter().find_map(|source| {
                    let BindingFromIr::Component { component, provide } = &source.from else {
                        return None;
                    };
                    let moniker = child_monikers.get(component)?;
                    (assignments.get(*moniker)? == site_id).then_some((
                        *component,
                        *moniker,
                        provide.as_str(),
                    ))
                })
            else {
                continue;
            };
            let protocol = match output.decl.kind.transport() {
                CapabilityTransport::Http => "http",
                CapabilityTransport::NonNetwork => continue,
                _ => continue,
            };
            let export =
                dynamic_proxy_export_record(fragment, component_id, provide_name, protocol)
                    .ok_or_else(|| {
                        protocol_error(
                            ProtocolErrorCode::ControlStateUnavailable,
                            &format!(
                                "dynamic export `{name}` on component `{component_moniker}` could \
                                 not be resolved to a concrete network endpoint"
                            ),
                        )
                    })?;
            proxy_exports.insert(name.clone(), export);
        }
        for overlay in overlays {
            let DynamicOverlayAction::ExportPeer { link } = &overlay.action else {
                continue;
            };
            if link.provider_site != *site_id
                || !child_moniker_set.contains(link.provider_component.as_str())
            {
                continue;
            }
            if proxy_exports.contains_key(&link.export_name) {
                continue;
            }
            let component = fragment
                .components
                .iter()
                .find(|component| component.moniker == link.provider_component)
                .ok_or_else(|| {
                    protocol_error(
                        ProtocolErrorCode::ControlStateUnavailable,
                        &format!(
                            "dynamic export provider `{}` is missing from the live child fragment",
                            link.provider_component
                        ),
                    )
                })?;
            let export = dynamic_proxy_export_record(
                fragment,
                component.id,
                &link.provide,
                &link.protocol.to_string(),
            )
            .ok_or_else(|| {
                protocol_error(
                    ProtocolErrorCode::ControlStateUnavailable,
                    &format!(
                        "dynamic export `{}` on component `{}` could not be resolved to a \
                         concrete network endpoint",
                        link.export_name, link.provider_component
                    ),
                )
            })?;
            proxy_exports.insert(link.export_name.clone(), export);
        }
        let artifact_files = if desired_site_plan.site.kind == SiteKind::Kubernetes {
            project_kubernetes_dynamic_child_artifact_files(
                &desired_site_plan.artifact_files,
                &component_ids,
            )
            .map_err(|err| {
                protocol_error(
                    ProtocolErrorCode::ControlStateUnavailable,
                    &format!(
                        "failed to project kubernetes child artifact for site `{site_id}`: {err}"
                    ),
                )
            })?
        } else {
            desired_site_plan.artifact_files.clone()
        };
        site_plans.push(DynamicSitePlanRecord {
            site_id: site_id.clone(),
            kind: desired_site_plan.site.kind,
            router_identity_id: desired_site_plan.router_identity_id.clone(),
            component_ids,
            assigned_components,
            artifact_files,
            desired_artifact_files: desired_site_plan.artifact_files.clone(),
            proxy_exports,
            routed_inputs: routed_inputs
                .iter()
                .filter(|input| input.component == child_monikers[&fragment.root_component_id])
                .filter(|input| {
                    assignments
                        .get(input.component.as_str())
                        .is_some_and(|assigned_site| assigned_site == site_id)
                })
                .cloned()
                .collect(),
        });
    }
    Ok(site_plans)
}

pub(super) fn child_input_binding_records(
    scenario: &Scenario,
    resolved_bindings: &[ResolvedTemplateBinding],
) -> Vec<ChildInputBindingRecord> {
    resolved_bindings
        .iter()
        .map(|binding| ChildInputBindingRecord {
            slot: binding.slot_name.clone(),
            decl: binding.slot_decl.decl.clone(),
            sources: binding
                .sources
                .iter()
                .map(|source| ChildInputBindingSourceRecord {
                    from: BindingFromIr::from(&source.from),
                    component_moniker: match &source.from {
                        BindingFrom::Component(ProvideRef { component, .. }) => {
                            Some(scenario.component(*component).moniker.to_string())
                        }
                        _ => None,
                    },
                    weak: source.weak,
                })
                .collect(),
        })
        .collect()
}

pub(super) fn dynamic_input_route_records(
    assignments: &BTreeMap<String, String>,
    fragment: &LiveScenarioFragment,
    input_bindings: &[ChildInputBindingRecord],
) -> Vec<DynamicInputRouteRecord> {
    let Some(root_component) = fragment
        .components
        .iter()
        .find(|component| component.id == fragment.root_component_id)
    else {
        return Vec::new();
    };
    let Some(child_site) = assignments.get(root_component.moniker.as_str()) else {
        return Vec::new();
    };
    let fragment_components = fragment
        .components
        .iter()
        .map(|component| component.moniker.as_str())
        .collect::<BTreeSet<_>>();
    input_bindings
        .iter()
        .filter_map(|binding| {
            let [source] = binding.sources.as_slice() else {
                return None;
            };
            let BindingFromIr::Component { provide, .. } = &source.from else {
                return None;
            };
            let provider_component = source.component_moniker.as_ref()?;
            if fragment_components.contains(provider_component.as_str()) {
                return None;
            }
            let provider_site = assignments.get(provider_component.as_str())?;
            let protocol = match binding.decl.kind.transport() {
                CapabilityTransport::Http => "http",
                CapabilityTransport::NonNetwork => return None,
                _ => return None,
            };
            (provider_site == child_site).then(|| DynamicInputRouteRecord {
                component: root_component.moniker.clone(),
                slot: binding.slot.clone(),
                provider_component: provider_component.clone(),
                protocol: protocol.to_string(),
                capability_kind: binding.decl.kind.to_string(),
                capability_profile: binding.decl.profile.clone(),
                target: DynamicInputRouteTarget::ComponentProvide {
                    provide: provide.clone(),
                },
            })
        })
        .collect()
}

pub(super) fn dynamic_proxy_export_record(
    fragment: &LiveScenarioFragment,
    component_id: usize,
    provide_name: &str,
    protocol: &str,
) -> Option<DynamicProxyExportRecord> {
    let component = fragment
        .components
        .iter()
        .find(|component| component.id == component_id)?;
    let network = component.program.as_ref()?.network()?;
    let protocol = protocol.parse::<NetworkProtocol>().ok()?;
    let resolve_provide = |name: &str| {
        let provide = component.provides.get(name)?;
        let endpoint_name = provide.endpoint.as_deref()?;
        let endpoint = network
            .endpoints
            .iter()
            .find(|endpoint| endpoint.name == endpoint_name)?;
        Some((provide, endpoint))
    };
    let (provide_name, provide, endpoint) =
        if let Some((provide, endpoint)) = resolve_provide(provide_name) {
            (provide_name.to_string(), provide, endpoint)
        } else {
            let mut candidates = component
                .provides
                .iter()
                .filter_map(|(name, provide)| {
                    let endpoint_name = provide.endpoint.as_deref()?;
                    let endpoint = network
                        .endpoints
                        .iter()
                        .find(|endpoint| endpoint.name == endpoint_name)?;
                    (endpoint.protocol == protocol).then_some((name.clone(), provide, endpoint))
                })
                .collect::<Vec<_>>();
            if candidates.len() != 1 {
                return None;
            }
            let (name, provide, endpoint) = candidates.pop()?;
            (name, provide, endpoint)
        };
    Some(DynamicProxyExportRecord {
        component_id,
        component: component.moniker.clone(),
        provide: provide_name,
        protocol: protocol.to_string(),
        capability_kind: provide.decl.kind.to_string(),
        capability_profile: provide.decl.profile.clone(),
        target_port: endpoint.port,
    })
}

pub(super) fn dynamic_overlay_records(
    links: &[RunLink],
    fragment: &LiveScenarioFragment,
) -> Vec<DynamicOverlayRecord> {
    let child_monikers = fragment
        .components
        .iter()
        .map(|component| component.moniker.as_str())
        .collect::<BTreeSet<_>>();
    let mut overlays = Vec::new();
    for link in links {
        let consumer_in_child = child_monikers.contains(link.consumer_component.as_str());
        let provider_in_child = child_monikers.contains(link.provider_component.as_str());
        if consumer_in_child || provider_in_child {
            overlays.push(DynamicOverlayRecord {
                overlay_id: format!(
                    "child:{}:consumer:{}:{}",
                    fragment.root_component_id, link.consumer_site, link.external_slot_name
                ),
                site_id: link.consumer_site.clone(),
                action: DynamicOverlayAction::ExternalSlot { link: link.clone() },
            });
        }
        if consumer_in_child || provider_in_child {
            overlays.push(DynamicOverlayRecord {
                overlay_id: format!(
                    "child:{}:provider:{}:{}",
                    fragment.root_component_id, link.provider_site, link.export_name
                ),
                site_id: link.provider_site.clone(),
                action: DynamicOverlayAction::ExportPeer { link: link.clone() },
            });
        }
    }
    overlays
}

pub(super) fn create_child_response(child: &LiveChildRecord) -> CreateChildResponse {
    CreateChildResponse {
        child: ChildHandle {
            name: child.name.clone(),
            selector: format!("children.{}", child.name),
        },
        outputs: child
            .outputs
            .iter()
            .map(|(name, output)| {
                (
                    name.clone(),
                    amber_mesh::component_protocol::OutputHandle {
                        selector: output.selector.clone(),
                        handle: output.handle.clone(),
                    },
                )
            })
            .collect(),
    }
}

pub(super) fn extract_live_child_fragment(
    state: &mut FrameworkControlState,
    compiled: &CompiledScenario,
    synthetic_sources: &BTreeMap<String, SyntheticSourceRecord>,
    authority_component: &Component,
    child_name: &str,
    child_id: u64,
) -> std::result::Result<
    (LiveScenarioFragment, BTreeMap<String, OutputHandleRecord>),
    ProtocolErrorResponse,
> {
    let wrapper_root = compiled.scenario_ir().root;
    let old_child_root = compiled
        .scenario()
        .component(ComponentId(wrapper_root))
        .children
        .first()
        .copied()
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                "synthetic wrapper compiled without a child root",
            )
        })?
        .0;
    let mut id_map = BTreeMap::new();
    for component in &compiled.scenario_ir().components {
        if component.id == wrapper_root {
            continue;
        }
        id_map.insert(component.id, state.next_component_id);
        state.next_component_id += 1;
    }

    let mut components = compiled
        .scenario_ir()
        .components
        .iter()
        .filter(|component| component.id != wrapper_root)
        .map(|component| {
            let mut component = component.clone();
            component.id = *id_map
                .get(&component.id)
                .expect("component ids should be allocated");
            component.parent = match component.parent {
                Some(parent) if parent == wrapper_root => Some(authority_component.id.0),
                Some(parent) => Some(
                    *id_map
                        .get(&parent)
                        .expect("internal child parent should be remapped"),
                ),
                None => None,
            };
            component.children = component
                .children
                .iter()
                .map(|child| {
                    *id_map
                        .get(child)
                        .expect("internal child edges should be remapped")
                })
                .collect();
            component.moniker =
                joined_moniker(authority_component.moniker.as_str(), &component.moniker);
            component
        })
        .collect::<Vec<_>>();
    components.sort_by(|left, right| left.id.cmp(&right.id));

    let mut bindings = Vec::new();
    for binding in &compiled.scenario_ir().bindings {
        if binding.to.component == wrapper_root {
            continue;
        }
        let mut rewritten = binding.clone();
        rewritten.to.component = *id_map
            .get(&binding.to.component)
            .expect("binding target should be remapped");
        let source_child_id = match &mut rewritten.from {
            BindingFromIr::Component { component, provide } if *component == wrapper_root => {
                let synthetic = synthetic_sources.get(provide).ok_or_else(|| {
                    protocol_error(
                        ProtocolErrorCode::ControlStateUnavailable,
                        &format!("missing synthetic source mapping for `{provide}`"),
                    )
                })?;
                rewritten.from = BindingFromIr::from(&synthetic.actual_source);
                rewritten.weak = synthetic.weak;
                synthetic.source_child_id
            }
            BindingFromIr::Resource {
                component,
                resource,
            } if *component == wrapper_root => {
                let synthetic = synthetic_sources.get(resource).ok_or_else(|| {
                    protocol_error(
                        ProtocolErrorCode::ControlStateUnavailable,
                        &format!("missing synthetic source mapping for `{resource}`"),
                    )
                })?;
                rewritten.from = BindingFromIr::from(&synthetic.actual_source);
                rewritten.weak = synthetic.weak;
                synthetic.source_child_id
            }
            BindingFromIr::External { slot } if slot.component == wrapper_root => {
                let synthetic = synthetic_sources.get(&slot.slot).ok_or_else(|| {
                    protocol_error(
                        ProtocolErrorCode::ControlStateUnavailable,
                        &format!("missing synthetic source mapping for `{}`", slot.slot),
                    )
                })?;
                rewritten.from = BindingFromIr::from(&synthetic.actual_source);
                rewritten.weak = synthetic.weak;
                synthetic.source_child_id
            }
            BindingFromIr::Framework {
                authority_realm, ..
            } if *authority_realm == wrapper_root => {
                let Some(synthetic) = synthetic_sources.values().find(|source| {
                    source.slot_name == binding.to.slot
                        && matches!(source.actual_source, BindingFrom::Framework(_))
                }) else {
                    return Err(protocol_error(
                        ProtocolErrorCode::ControlStateUnavailable,
                        &format!(
                            "missing framework synthetic source mapping for slot `{}`",
                            binding.to.slot
                        ),
                    ));
                };
                rewritten.from = BindingFromIr::from(&synthetic.actual_source);
                rewritten.weak = synthetic.weak;
                synthetic.source_child_id
            }
            BindingFromIr::Framework {
                authority_realm, ..
            } => {
                if let Some(remapped) = id_map.get(authority_realm) {
                    *authority_realm = *remapped;
                }
                None
            }
            BindingFromIr::Component { component, .. } => {
                *component = *id_map
                    .get(component)
                    .expect("internal binding source should be remapped");
                None
            }
            BindingFromIr::Resource { component, .. } => {
                *component = *id_map
                    .get(component)
                    .expect("internal binding resource source should be remapped");
                None
            }
            BindingFromIr::External { .. } => None,
        };
        bindings.push(LiveFragmentBindingRecord {
            binding: rewritten,
            source_child_id,
        });
    }

    let mut outputs = BTreeMap::new();
    for export in &compiled.scenario_ir().exports {
        let sources = if export.from.component == wrapper_root {
            let synthetic = synthetic_sources.get(&export.from.provide).ok_or_else(|| {
                protocol_error(
                    ProtocolErrorCode::ControlStateUnavailable,
                    &format!(
                        "missing synthetic mapping for exported source `{}`",
                        export.from.provide
                    ),
                )
            })?;
            vec![live_binding_source_record(&synthetic.actual_source, false)]
        } else {
            let actual_component_id = *id_map.get(&export.from.component).ok_or_else(|| {
                protocol_error(
                    ProtocolErrorCode::ControlStateUnavailable,
                    "export source component is missing from child id map",
                )
            })?;
            vec![LiveBindingSourceRecord {
                from: BindingFromIr::Component {
                    component: actual_component_id,
                    provide: export.from.provide.clone(),
                },
                weak: false,
            }]
        };
        outputs.insert(
            export.name.clone(),
            OutputHandleRecord {
                selector: format!("children.{child_name}.exports.{}", export.name),
                handle: Some(format!("h_{child_id}_{}", export.name)),
                decl: export.capability.clone(),
                sources,
            },
        );
    }

    Ok((
        LiveScenarioFragment {
            root_component_id: *id_map
                .get(&old_child_root)
                .expect("child root id should be remapped"),
            components,
            bindings,
        },
        outputs,
    ))
}

pub(super) async fn compile_frozen_manifest(
    state: &FrameworkControlState,
    root: ManifestRef,
    extra_manifests: BTreeMap<String, Manifest>,
) -> std::result::Result<CompiledScenario, ProtocolErrorResponse> {
    let backend = Arc::new(FrozenCatalogBackend {
        entries: Arc::new(state.base_scenario.manifest_catalog.clone()),
        extra_manifests: Arc::new(extra_manifests),
    });
    let compiler = Compiler::new(
        Resolver::new().with_remote(RemoteResolver::new(
            frozen_catalog_schemes(state.base_scenario.manifest_catalog.values())
                .into_iter()
                .chain(["amber+framework".to_string()]),
            backend,
        )),
        DigestStore::default(),
    );
    let output = compiler
        .compile(root, CompileOptions::default())
        .await
        .map_err(|err| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &format!("failed to compile frozen manifest: {err:?}"),
            )
        })?;
    CompiledScenario::from_compile_output(&output).map_err(|err| {
        protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &format!("failed to materialize compiled scenario: {err}"),
        )
    })
}

pub(super) fn joined_moniker(parent: &str, child: &str) -> String {
    if parent == "/" {
        child.to_string()
    } else {
        format!("{parent}{child}")
    }
}

pub(super) fn child_state_keeps_capability_instances(state: ChildState) -> bool {
    matches!(
        state,
        ChildState::CreatePrepared | ChildState::CreateCommittedHidden | ChildState::Live
    )
}

pub(super) fn refresh_capability_instances(state: &mut FrameworkControlState) -> Result<()> {
    state.capability_instances = collect_capability_instances(state)?;
    Ok(())
}

pub(super) fn collect_capability_instances(
    state: &FrameworkControlState,
) -> Result<BTreeMap<String, CapabilityInstanceRecord>> {
    let active_children = all_child_records(state)
        .filter(|child| child_state_keeps_capability_instances(child.state))
        .collect::<Vec<_>>();

    let mut moniker_by_id = state
        .base_scenario
        .components
        .iter()
        .map(|component| (component.id, component.moniker.clone()))
        .collect::<BTreeMap<_, _>>();
    for child in &active_children {
        let Some(fragment) = child.fragment.as_ref() else {
            continue;
        };
        moniker_by_id.extend(
            fragment
                .components
                .iter()
                .map(|component| (component.id, component.moniker.clone())),
        );
    }

    let mut site_by_moniker = state.placement.assignments.clone();
    for child in &active_children {
        site_by_moniker.extend(child.assignments.clone());
    }

    let mut records = BTreeMap::new();
    for binding in &state.base_scenario.bindings {
        collect_capability_instance_from_binding(
            &mut records,
            binding,
            &moniker_by_id,
            &site_by_moniker,
            state.generation,
        )?;
    }
    for child in &active_children {
        let Some(fragment) = child.fragment.as_ref() else {
            continue;
        };
        for binding in &fragment.bindings {
            collect_capability_instance_from_binding(
                &mut records,
                &binding.binding,
                &moniker_by_id,
                &site_by_moniker,
                state.generation,
            )?;
        }
    }
    Ok(records)
}

pub(super) fn collect_capability_instance_from_binding(
    records: &mut BTreeMap<String, CapabilityInstanceRecord>,
    binding: &BindingIr,
    moniker_by_id: &BTreeMap<usize, String>,
    site_by_moniker: &BTreeMap<String, String>,
    generation: u64,
) -> Result<()> {
    let BindingFromIr::Framework {
        authority_realm,
        capability,
    } = &binding.from
    else {
        return Ok(());
    };
    if capability != "component" {
        return Ok(());
    }

    let authority_realm_moniker = moniker_by_id.get(authority_realm).cloned().ok_or_else(|| {
        miette::miette!(
            "framework.component authority realm id {authority_realm} is missing from the \
             authoritative live graph"
        )
    })?;
    let recipient_component_moniker = moniker_by_id
        .get(&binding.to.component)
        .cloned()
        .ok_or_else(|| {
            miette::miette!(
                "framework.component recipient component id {} is missing from the authoritative \
                 live graph",
                binding.to.component
            )
        })?;
    let recipient_site_id = site_by_moniker
        .get(&recipient_component_moniker)
        .cloned()
        .ok_or_else(|| {
            miette::miette!(
                "framework.component recipient `{recipient_component_moniker}` is missing a site \
                 assignment in the authoritative live graph"
            )
        })?;
    let cap_instance_id = framework_cap_instance_id(
        authority_realm_moniker.as_str(),
        recipient_component_moniker.as_str(),
        &binding.to.component.to_string(),
        &binding.to.slot,
        capability,
    );
    records.insert(
        cap_instance_id.clone(),
        CapabilityInstanceRecord {
            cap_instance_id: cap_instance_id.clone(),
            route_id: cap_instance_id,
            authority_realm_id: *authority_realm,
            authority_realm_moniker,
            recipient_component_id: binding.to.component,
            recipient_component_moniker: recipient_component_moniker.clone(),
            recipient_peer_id: recipient_component_moniker,
            recipient_site_id,
            capability: capability.clone(),
            slot: binding.to.slot.clone(),
            generation,
        },
    );
    Ok(())
}

pub(super) fn template_mode(template: &ChildTemplate) -> TemplateMode {
    match template.manifests.as_ref() {
        Some(manifests) if manifests.len() == 1 => TemplateMode::Exact,
        Some(_) => TemplateMode::Bounded,
        None => TemplateMode::Open,
    }
}

pub(super) fn manifest_ref_from_source(
    source_ref: &str,
    digest: amber_manifest::ManifestDigest,
) -> std::result::Result<ManifestRef, ProtocolErrorResponse> {
    let url = url::Url::parse(source_ref).map_err(|err| {
        protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &format!("invalid frozen manifest catalog source_ref `{source_ref}`: {err}"),
        )
    })?;
    Ok(ManifestRef::new(url, Some(digest)))
}

pub(super) fn template_manifest_description(
    scenario: &Scenario,
    template: &ChildTemplate,
) -> std::result::Result<TemplateManifestDescription, ProtocolErrorResponse> {
    let mut description = TemplateManifestDescription {
        mode: template_mode(template),
        manifest: None,
        manifests: Vec::new(),
    };
    match template.manifests.as_ref() {
        Some(manifests) if manifests.len() == 1 => {
            let entry = scenario
                .manifest_catalog
                .get(&manifests[0])
                .ok_or_else(|| {
                    protocol_error(
                        ProtocolErrorCode::ControlStateUnavailable,
                        "frozen manifest catalog entry is missing",
                    )
                })?;
            description.manifest = Some(manifest_ref_from_source(&entry.source_ref, entry.digest)?);
        }
        Some(manifests) => {
            description.manifests = manifests
                .iter()
                .map(|key| {
                    let entry = scenario.manifest_catalog.get(key).ok_or_else(|| {
                        protocol_error(
                            ProtocolErrorCode::ControlStateUnavailable,
                            &format!("frozen manifest catalog entry `{key}` is missing"),
                        )
                    })?;
                    manifest_ref_from_source(&entry.source_ref, entry.digest)
                })
                .collect::<std::result::Result<Vec<_>, _>>()?;
        }
        None => {}
    }
    Ok(description)
}

#[derive(Clone)]
pub(super) struct ResolvedBindingSource {
    pub(super) from: BindingFrom,
    pub(super) weak: bool,
}

#[derive(Clone)]
pub(super) struct BindableSourceCandidate {
    pub(super) selector: String,
    pub(super) handle: Option<String>,
    pub(super) decl: CapabilityDecl,
    pub(super) sources: Vec<ResolvedBindingSource>,
    pub(super) source_child_id: Option<u64>,
}

pub(super) fn placement_file_from_state(state: &FrameworkControlState) -> PlacementFile {
    let mut components = state.placement.placement_components.clone();
    for child in visible_child_records(state) {
        components.extend(child.assignments.clone());
    }
    PlacementFile {
        schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
        version: amber_compiler::run_plan::PLACEMENT_VERSION,
        sites: state.placement.offered_sites.clone(),
        defaults: state.placement.defaults.clone(),
        components,
        dynamic_capabilities: None,
        framework_children: None,
    }
}

pub(super) fn run_plan_activation_from_state(
    state: &FrameworkControlState,
) -> RunPlanActivationState {
    let mut initial_active_sites = state.placement.initial_active_sites.clone();
    let mut dynamic_enabled_sites = state.placement.dynamic_enabled_sites.clone();
    let mut active_site_capabilities = state.placement.active_site_capabilities.clone();
    for site_id in state.placement.placement_components.values() {
        if !initial_active_sites.contains(site_id) {
            initial_active_sites.push(site_id.clone());
        }
        if !dynamic_enabled_sites.contains(site_id) {
            dynamic_enabled_sites.push(site_id.clone());
        }
        active_site_capabilities
            .entry(site_id.clone())
            .or_insert(ActiveSiteCapabilities {
                cross_site_routing: true,
                dynamic_workloads: true,
                privileged_control: true,
            });
    }
    RunPlanActivationState {
        standby_sites: state.placement.standby_sites.clone(),
        initial_active_sites,
        dynamic_enabled_sites,
        control_only_sites: state.placement.control_only_sites.clone(),
        active_site_capabilities,
    }
}

pub(super) fn live_assignment_map(state: &FrameworkControlState) -> BTreeMap<String, String> {
    let mut assignments = state.placement.assignments.clone();
    for child in visible_child_records(state) {
        assignments.extend(child.assignments.clone());
    }
    assignments
}

pub(super) fn scenario_with_fragment(
    current_live_scenario_ir: &ScenarioIr,
    fragment: &LiveScenarioFragment,
) -> std::result::Result<Scenario, ProtocolErrorResponse> {
    let mut scenario_ir = current_live_scenario_ir.clone();
    scenario_ir.components.extend(fragment.components.clone());
    scenario_ir.bindings.extend(
        fragment
            .bindings
            .iter()
            .map(|binding| binding.binding.clone()),
    );
    for component in &mut scenario_ir.components {
        component.children.clear();
    }
    let parent_edges = scenario_ir
        .components
        .iter()
        .filter_map(|component| component.parent.map(|parent| (parent, component.id)))
        .collect::<Vec<_>>();
    for (parent, child) in parent_edges {
        let parent_component = scenario_ir
            .components
            .iter_mut()
            .find(|component| component.id == parent)
            .ok_or_else(|| {
                protocol_error(
                    ProtocolErrorCode::ControlStateUnavailable,
                    &format!(
                        "live fragment references missing parent component id {parent} for child \
                         {child}"
                    ),
                )
            })?;
        parent_component.children.push(child);
    }
    Scenario::try_from(scenario_ir).map_err(|err| {
        protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &format!("failed to materialize combined live scenario: {err}"),
        )
    })
}

pub(super) fn live_scenario_ir(
    state: &FrameworkControlState,
) -> std::result::Result<ScenarioIr, ProtocolErrorResponse> {
    let mut components = state
        .base_scenario
        .components
        .iter()
        .cloned()
        .map(|component| (component.id, component))
        .collect::<BTreeMap<_, _>>();
    let mut bindings = state.base_scenario.bindings.clone();

    for child in visible_child_records(state) {
        let Some(fragment) = child.fragment.as_ref() else {
            continue;
        };
        for component in &fragment.components {
            components.insert(component.id, component.clone());
        }
        let mut seen_binding_keys = bindings
            .iter()
            .map(binding_identity_key)
            .collect::<BTreeSet<_>>();
        for binding in &fragment.bindings {
            let key = binding_identity_key(&binding.binding);
            if seen_binding_keys.insert(key) {
                bindings.push(binding.binding.clone());
            }
        }
    }

    for component in components.values_mut() {
        component.children.clear();
    }
    let parent_edges = components
        .values()
        .filter_map(|component| component.parent.map(|parent| (parent, component.id)))
        .collect::<Vec<_>>();
    for (parent, child) in parent_edges {
        let parent_component = components.get_mut(&parent).ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &format!(
                    "live fragment references missing parent component id {parent} for child \
                     {child}"
                ),
            )
        })?;
        parent_component.children.push(child);
    }
    let monikers = components
        .iter()
        .map(|(id, component)| (*id, component.moniker.clone()))
        .collect::<BTreeMap<_, _>>();
    for component in components.values_mut() {
        component.children.sort_by(|left, right| {
            let left_moniker = monikers
                .get(left)
                .map(|moniker| moniker.as_str())
                .unwrap_or("/");
            let right_moniker = monikers
                .get(right)
                .map(|moniker| moniker.as_str())
                .unwrap_or("/");
            left_moniker.cmp(right_moniker)
        });
    }

    Ok(ScenarioIr {
        schema: state.base_scenario.schema.clone(),
        version: state.base_scenario.version,
        root: state.base_scenario.root,
        components: components.into_values().collect(),
        bindings,
        exports: state.base_scenario.exports.clone(),
        manifest_catalog: state.base_scenario.manifest_catalog.clone(),
    })
}

pub(super) fn decode_live_scenario(
    state: &FrameworkControlState,
) -> std::result::Result<Scenario, ProtocolErrorResponse> {
    Scenario::try_from(live_scenario_ir(state)?).map_err(|err| {
        protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &format!("failed to decode authoritative live scenario: {err}"),
        )
    })
}

pub(super) fn normalize_scenario_ir_order(scenario_ir: &mut ScenarioIr) -> BTreeMap<usize, usize> {
    scenario_ir.components.sort_by(|left, right| {
        left.moniker
            .cmp(&right.moniker)
            .then(left.id.cmp(&right.id))
    });
    let id_map = scenario_ir
        .components
        .iter()
        .enumerate()
        .map(|(new_id, component)| (component.id, new_id))
        .collect::<BTreeMap<_, _>>();
    scenario_ir.root = *id_map
        .get(&scenario_ir.root)
        .expect("snapshot root component should remain present");

    for component in &mut scenario_ir.components {
        component.id = *id_map
            .get(&component.id)
            .expect("snapshot component id should remain present");
        component.parent = component.parent.map(|parent| {
            *id_map
                .get(&parent)
                .expect("snapshot parent component id should remain present")
        });
        for child in &mut component.children {
            *child = *id_map
                .get(child)
                .expect("snapshot child component id should remain present");
        }
    }

    let monikers = scenario_ir
        .components
        .iter()
        .map(|component| (component.id, component.moniker.clone()))
        .collect::<BTreeMap<_, _>>();
    for component in &mut scenario_ir.components {
        component.children.sort_by(|left, right| {
            let left_moniker = monikers.get(left).map(String::as_str).unwrap_or("/");
            let right_moniker = monikers.get(right).map(String::as_str).unwrap_or("/");
            left_moniker.cmp(right_moniker)
        });
    }
    for binding in &mut scenario_ir.bindings {
        match &mut binding.from {
            BindingFromIr::Component { component, .. }
            | BindingFromIr::Resource { component, .. } => {
                *component = *id_map
                    .get(component)
                    .expect("snapshot binding source component id should remain present");
            }
            BindingFromIr::Framework {
                authority_realm, ..
            } => {
                *authority_realm = *id_map
                    .get(authority_realm)
                    .expect("snapshot framework authority realm should remain present");
            }
            BindingFromIr::External { slot } => {
                slot.component = *id_map
                    .get(&slot.component)
                    .expect("snapshot external slot component id should remain present");
            }
        }
        binding.to.component = *id_map
            .get(&binding.to.component)
            .expect("snapshot binding target component id should remain present");
    }
    scenario_ir.bindings.sort_by(|left, right| {
        binding_sort_key(left, &monikers).cmp(&binding_sort_key(right, &monikers))
    });
    for export in &mut scenario_ir.exports {
        export.from.component = *id_map
            .get(&export.from.component)
            .expect("snapshot export source component id should remain present");
    }
    scenario_ir
        .exports
        .sort_by(|left, right| left.name.cmp(&right.name));
    id_map
}

pub(super) fn binding_sort_key(binding: &BindingIr, monikers: &BTreeMap<usize, String>) -> String {
    let source = match &binding.from {
        BindingFromIr::Component { component, provide } => format!(
            "component:{}:{provide}",
            monikers.get(component).map(String::as_str).unwrap_or("/")
        ),
        BindingFromIr::Resource {
            component,
            resource,
        } => format!(
            "resource:{}:{resource}",
            monikers.get(component).map(String::as_str).unwrap_or("/")
        ),
        BindingFromIr::Framework {
            capability,
            authority_realm,
        } => format!(
            "framework:{}:{capability}",
            monikers
                .get(authority_realm)
                .map(String::as_str)
                .unwrap_or("/")
        ),
        BindingFromIr::External { slot } => format!("external:{}:{}", slot.component, slot.slot),
    };
    format!(
        "{}:{}:{}:{}",
        monikers
            .get(&binding.to.component)
            .map(String::as_str)
            .unwrap_or("/"),
        binding.to.slot,
        source,
        binding.weak
    )
}

pub(super) fn binding_identity_key(binding: &BindingIr) -> String {
    serde_json::to_string(binding).expect("binding identity should serialize")
}

pub(super) fn live_child_component_owner(
    state: &FrameworkControlState,
    component_id: usize,
) -> Option<u64> {
    all_child_records(state)
        .filter_map(|child| {
            let fragment = child.fragment.as_ref()?;
            fragment
                .components
                .iter()
                .any(|component| component.id == component_id)
                .then_some(child.child_id)
        })
        .next()
}

pub(super) fn output_sources_from_record(
    output: &OutputHandleRecord,
) -> std::result::Result<Vec<ResolvedBindingSource>, ProtocolErrorResponse> {
    output
        .sources
        .iter()
        .map(|source| {
            Ok(ResolvedBindingSource {
                from: binding_from_from_ir(source.from.clone())?,
                weak: source.weak,
            })
        })
        .collect()
}

pub(super) fn bindable_source_candidates(
    scenario: &Scenario,
    scenario_ir: &ScenarioIr,
    state: &FrameworkControlState,
    authority_realm: ComponentId,
) -> std::result::Result<Vec<BindableSourceCandidate>, ProtocolErrorResponse> {
    let component = scenario.component(authority_realm);
    let mut out = Vec::new();

    for (name, slot) in &component.slots {
        out.push(BindableSourceCandidate {
            selector: format!("slots.{name}"),
            handle: None,
            decl: slot.decl.clone(),
            sources: slot_binding_sources(scenario, authority_realm, name),
            source_child_id: None,
        });
    }

    out.extend(
        component
            .provides
            .iter()
            .map(|(name, provide)| BindableSourceCandidate {
                selector: format!("provides.{name}"),
                handle: None,
                decl: provide.decl.clone(),
                sources: vec![ResolvedBindingSource {
                    from: BindingFrom::Component(ProvideRef {
                        component: authority_realm,
                        name: name.clone(),
                    }),
                    weak: false,
                }],
                source_child_id: None,
            }),
    );
    out.extend(
        component
            .resources
            .iter()
            .map(|(name, resource)| BindableSourceCandidate {
                selector: format!("resources.{name}"),
                handle: None,
                decl: CapabilityDecl::builder().kind(resource.kind).build(),
                sources: vec![ResolvedBindingSource {
                    from: BindingFrom::Resource(ResourceRef {
                        component: authority_realm,
                        name: name.clone(),
                    }),
                    weak: false,
                }],
                source_child_id: None,
            }),
    );
    out.extend(static_child_export_candidates(
        scenario,
        scenario_ir,
        state,
        authority_realm,
    )?);

    for child in
        visible_child_records(state).filter(|child| child.authority_realm_id == authority_realm.0)
    {
        for (export_name, output) in &child.outputs {
            out.push(BindableSourceCandidate {
                selector: format!("children.{}.exports.{export_name}", child.name),
                handle: output.handle.clone(),
                decl: output.decl.clone(),
                sources: output_sources_from_record(output)?,
                source_child_id: Some(child.child_id),
            });
        }
    }

    if authority_realm == scenario.root && scenario.component(scenario.root).program.is_some() {
        out.extend(
            scenario
                .bindings
                .iter()
                .filter_map(|binding| match &binding.from {
                    BindingFrom::External(slot) if slot.component == scenario.root => {
                        Some((slot.name.clone(), binding.to.name.clone()))
                    }
                    _ => None,
                })
                .filter_map(|(external_name, slot_name)| {
                    component
                        .slots
                        .get(slot_name.as_str())
                        .map(|slot| BindableSourceCandidate {
                            selector: format!("external.{external_name}"),
                            handle: None,
                            decl: slot.decl.clone(),
                            sources: vec![ResolvedBindingSource {
                                from: BindingFrom::External(SlotRef {
                                    component: scenario.root,
                                    name: external_name,
                                }),
                                weak: true,
                            }],
                            source_child_id: None,
                        })
                }),
        );
    }

    Ok(out)
}

pub(super) fn slot_binding_sources(
    scenario: &Scenario,
    component_id: ComponentId,
    slot_name: &str,
) -> Vec<ResolvedBindingSource> {
    scenario
        .bindings
        .iter()
        .filter(|binding| binding.to.component == component_id && binding.to.name == slot_name)
        .map(|binding| ResolvedBindingSource {
            from: binding.from.clone(),
            weak: binding.weak,
        })
        .collect()
}

pub(super) fn static_child_export_candidates(
    scenario: &Scenario,
    scenario_ir: &ScenarioIr,
    state: &FrameworkControlState,
    authority_realm: ComponentId,
) -> std::result::Result<Vec<BindableSourceCandidate>, ProtocolErrorResponse> {
    let authority_component = scenario.component(authority_realm);
    let authority_component_ir = component_ir(scenario_ir, authority_realm)?;
    let dynamic_child_roots = state
        .live_children
        .iter()
        .chain(state.pending_destroys.iter().map(|record| &record.child))
        .filter(|child| child.authority_realm_id == authority_realm.0)
        .filter(|child| child_is_visible(child))
        .filter_map(|child| {
            child
                .fragment
                .as_ref()
                .map(|fragment| fragment.root_component_id)
        })
        .collect::<BTreeSet<_>>();
    let mut out = Vec::new();

    for child_id in &authority_component_ir.children {
        if dynamic_child_roots.contains(child_id) {
            continue;
        }
        let child_component_id = ComponentId(*child_id);
        let child_component = scenario.component(child_component_id);
        let Some(child_name) = child_alias(
            authority_component.moniker.as_str(),
            child_component.moniker.as_str(),
        ) else {
            continue;
        };
        let child_component_ir = component_ir(scenario_ir, child_component_id)?;
        for export_name in child_component_ir.exports.keys() {
            let resolved = resolve_component_export_candidate(
                scenario,
                scenario_ir,
                child_component_id,
                export_name,
            )?;
            out.push(BindableSourceCandidate {
                selector: format!("children.{child_name}.exports.{export_name}"),
                handle: None,
                decl: resolved.decl,
                sources: resolved.sources,
                source_child_id: None,
            });
        }
    }

    Ok(out)
}

pub(super) fn component_ir(
    scenario_ir: &ScenarioIr,
    component_id: ComponentId,
) -> std::result::Result<&ComponentIr, ProtocolErrorResponse> {
    scenario_ir
        .components
        .iter()
        .find(|component| component.id == component_id.0)
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &format!(
                    "component id {} is missing from frozen scenario IR",
                    component_id.0
                ),
            )
        })
}

pub(super) struct ResolvedComponentExportCandidate {
    decl: CapabilityDecl,
    sources: Vec<ResolvedBindingSource>,
}

pub(super) fn resolve_component_export_candidate(
    scenario: &Scenario,
    scenario_ir: &ScenarioIr,
    component_id: ComponentId,
    export_name: &str,
) -> std::result::Result<ResolvedComponentExportCandidate, ProtocolErrorResponse> {
    resolve_component_export_candidate_inner(
        scenario,
        scenario_ir,
        component_id,
        export_name,
        &mut BTreeSet::new(),
    )
}

pub(super) fn resolve_component_export_candidate_inner(
    scenario: &Scenario,
    scenario_ir: &ScenarioIr,
    component_id: ComponentId,
    export_name: &str,
    visited: &mut BTreeSet<(usize, String)>,
) -> std::result::Result<ResolvedComponentExportCandidate, ProtocolErrorResponse> {
    if !visited.insert((component_id.0, export_name.to_string())) {
        return Err(protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &format!(
                "component export cycle detected while resolving component {} export \
                 `{export_name}`",
                component_id.0
            ),
        ));
    }

    let result = resolve_component_export_candidate_target(
        scenario,
        scenario_ir,
        component_id,
        export_name,
        visited,
    );
    visited.remove(&(component_id.0, export_name.to_string()));
    result
}

pub(super) fn resolve_component_export_candidate_target(
    scenario: &Scenario,
    scenario_ir: &ScenarioIr,
    component_id: ComponentId,
    export_name: &str,
    visited: &mut BTreeSet<(usize, String)>,
) -> std::result::Result<ResolvedComponentExportCandidate, ProtocolErrorResponse> {
    let component = scenario.component(component_id);
    let component_ir = component_ir(scenario_ir, component_id)?;
    let target = component_ir.exports.get(export_name).ok_or_else(|| {
        protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &format!(
                "component {} export `{export_name}` is missing from frozen scenario IR",
                component_id.0
            ),
        )
    })?;

    match target {
        ComponentExportTargetIr::SelfProvide { provide } => {
            let provide_decl = component.provides.get(provide).ok_or_else(|| {
                protocol_error(
                    ProtocolErrorCode::ControlStateUnavailable,
                    &format!(
                        "component {} export `{export_name}` references missing provide \
                         `{provide}`",
                        component_id.0
                    ),
                )
            })?;
            Ok(ResolvedComponentExportCandidate {
                decl: provide_decl.decl.clone(),
                sources: vec![ResolvedBindingSource {
                    from: BindingFrom::Component(ProvideRef {
                        component: component_id,
                        name: provide.clone(),
                    }),
                    weak: false,
                }],
            })
        }
        ComponentExportTargetIr::SelfSlot { slot } => {
            let slot_decl = component.slots.get(slot).ok_or_else(|| {
                protocol_error(
                    ProtocolErrorCode::ControlStateUnavailable,
                    &format!(
                        "component {} export `{export_name}` references missing slot `{slot}`",
                        component_id.0
                    ),
                )
            })?;
            Ok(ResolvedComponentExportCandidate {
                decl: slot_decl.decl.clone(),
                sources: slot_binding_sources(scenario, component_id, slot),
            })
        }
        ComponentExportTargetIr::ChildExport { child, export } => {
            let parent_moniker = component.moniker.as_str();
            let child_component_id = component_ir
                .children
                .iter()
                .copied()
                .find(|child_id| {
                    child_alias(
                        parent_moniker,
                        scenario.component(ComponentId(*child_id)).moniker.as_str(),
                    ) == Some(child.as_str())
                })
                .map(ComponentId)
                .ok_or_else(|| {
                    protocol_error(
                        ProtocolErrorCode::ControlStateUnavailable,
                        &format!(
                            "component {} export `{export_name}` references missing child \
                             `{child}`",
                            component_id.0
                        ),
                    )
                })?;
            resolve_component_export_candidate_inner(
                scenario,
                scenario_ir,
                child_component_id,
                export,
                visited,
            )
        }
    }
}

pub(super) fn child_alias<'a>(parent_moniker: &str, child_moniker: &'a str) -> Option<&'a str> {
    if child_moniker == "/" {
        return None;
    }
    let remainder = if parent_moniker == "/" {
        child_moniker.strip_prefix('/')?
    } else {
        child_moniker
            .strip_prefix(parent_moniker)?
            .strip_prefix('/')?
    };
    remainder.split('/').find(|segment| !segment.is_empty())
}

pub(super) fn find_bindable_source<'a>(
    bindable_sources: &'a [BindableSourceCandidate],
    selector: &str,
) -> std::result::Result<&'a BindableSourceCandidate, ProtocolErrorResponse> {
    let candidate = bindable_sources
        .iter()
        .find(|candidate| candidate.selector == selector)
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::BindingSourceNotFound,
                &format!("binding source `{selector}` is not present in the authority realm"),
            )
        })?;
    if candidate.sources.is_empty() {
        return Err(protocol_error(
            ProtocolErrorCode::BindingSourceNotFound,
            &format!("binding source `{selector}` is currently unbound"),
        ));
    }
    Ok(candidate)
}

pub(super) fn find_bindable_source_by_handle<'a>(
    bindable_sources: &'a [BindableSourceCandidate],
    handle: &str,
) -> std::result::Result<&'a BindableSourceCandidate, ProtocolErrorResponse> {
    bindable_sources
        .iter()
        .find(|candidate| candidate.handle.as_deref() == Some(handle))
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::BindingSourceNotFound,
                &format!("binding handle `{handle}` is not valid in the authority realm"),
            )
        })
}

pub(super) fn runtime_backend_name(backend: &amber_manifest::RuntimeBackend) -> String {
    serde_json::to_value(backend)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "unknown".to_string())
}

pub(super) fn source_compatible(target: CapabilityDecl, candidate: CapabilityDecl) -> bool {
    target.kind == candidate.kind && target.profile == candidate.profile
}

pub(super) fn decode_base_scenario(
    state: &FrameworkControlState,
) -> std::result::Result<Scenario, ProtocolErrorResponse> {
    Scenario::try_from(state.base_scenario.clone()).map_err(|err| {
        protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &format!("failed to decode frozen base scenario: {err}"),
        )
    })
}

pub(super) fn binding_from_from_ir(
    from: BindingFromIr,
) -> std::result::Result<BindingFrom, ProtocolErrorResponse> {
    match from {
        BindingFromIr::Component { component, provide } => Ok(BindingFrom::Component(ProvideRef {
            component: ComponentId(component),
            name: provide,
        })),
        BindingFromIr::Resource {
            component,
            resource,
        } => Ok(BindingFrom::Resource(ResourceRef {
            component: ComponentId(component),
            name: resource,
        })),
        BindingFromIr::Framework {
            capability,
            authority_realm,
        } => {
            let capability =
                FrameworkCapabilityName::try_from(capability.as_str()).map_err(|_| {
                    protocol_error(
                        ProtocolErrorCode::ControlStateUnavailable,
                        &format!("unknown framework capability `{capability}` in control state"),
                    )
                })?;
            Ok(BindingFrom::Framework(FrameworkRef {
                authority: ComponentId(authority_realm),
                capability,
            }))
        }
        BindingFromIr::External { slot } => Ok(BindingFrom::External(SlotRef {
            component: ComponentId(slot.component),
            name: slot.slot,
        })),
    }
}

pub(super) fn live_binding_source_record(
    from: &BindingFrom,
    weak: bool,
) -> LiveBindingSourceRecord {
    LiveBindingSourceRecord {
        from: BindingFromIr::from(from),
        weak,
    }
}

pub(crate) fn protocol_error(code: ProtocolErrorCode, message: &str) -> ProtocolErrorResponse {
    ProtocolErrorResponse {
        code,
        message: message.to_string(),
        details: None,
    }
}

#[derive(Clone)]
pub(super) struct FrozenCatalogBackend {
    entries: Arc<BTreeMap<String, ManifestCatalogEntryIr>>,
    extra_manifests: Arc<BTreeMap<String, Manifest>>,
}

impl Backend for FrozenCatalogBackend {
    fn resolve_url<'a>(
        &'a self,
        url: &'a url::Url,
    ) -> Pin<
        Box<
            dyn Future<Output = std::result::Result<Resolution, amber_resolver::Error>> + Send + 'a,
        >,
    > {
        Box::pin(async move {
            let key = url.to_string();
            if let Some(manifest) = self.extra_manifests.get(&key) {
                return Ok(Resolution {
                    url: url.clone(),
                    manifest: manifest.clone(),
                    source: Arc::<str>::from(""),
                    spans: Arc::new(ManifestSpans::default()),
                    bundle_source: None,
                });
            }
            let entry = self.entries.get(&key).ok_or_else(|| {
                amber_resolver::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("frozen manifest catalog is missing `{key}`"),
                ))
            })?;
            Ok(Resolution {
                url: url.clone(),
                manifest: entry.manifest.clone(),
                source: Arc::<str>::from(""),
                spans: Arc::new(ManifestSpans::default()),
                bundle_source: None,
            })
        })
    }
}

pub(super) fn frozen_catalog_schemes<'a>(
    entries: impl Iterator<Item = &'a ManifestCatalogEntryIr>,
) -> Vec<String> {
    let mut schemes = entries
        .filter_map(|entry| {
            url::Url::parse(&entry.source_ref)
                .ok()
                .map(|url| url.scheme().to_string())
        })
        .collect::<Vec<_>>();
    schemes.sort();
    schemes.dedup();
    schemes
}

#[derive(Clone)]
pub(super) struct ControlStateApp {
    pub(super) control_state: Arc<Mutex<FrameworkControlState>>,
    pub(super) client: ReqwestClient,
    pub(super) state_path: PathBuf,
    pub(super) run_root: PathBuf,
    pub(super) state_root: PathBuf,
    pub(super) mesh_scope: Arc<str>,
    pub(super) control_state_auth_token: Arc<str>,
    pub(super) authority_locks: Arc<Mutex<BTreeMap<usize, Arc<Mutex<()>>>>>,
    pub(super) bridge_proxies: Arc<Mutex<BTreeMap<BridgeProxyKey, BridgeProxyHandle>>>,
}

#[derive(Clone)]
pub(super) struct CcsApp {
    pub(super) client: ReqwestClient,
    pub(super) site_state_root: PathBuf,
    pub(super) control_state_url: Arc<str>,
    pub(super) router_auth_token: Arc<str>,
    pub(super) control_state_auth_token: Arc<str>,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct SiteManagerStateView {
    pub(super) status: String,
    pub(super) kind: SiteKind,
    pub(super) artifact_dir: String,
    pub(super) supervisor_pid: u32,
    #[serde(default)]
    pub(super) process_pid: Option<u32>,
    #[serde(default)]
    pub(super) compose_project: Option<String>,
    #[serde(default)]
    pub(super) kubernetes_namespace: Option<String>,
    #[serde(default)]
    pub(super) port_forward_pid: Option<u32>,
    #[serde(default)]
    pub(super) context: Option<String>,
    #[serde(default)]
    pub(super) router_control: Option<String>,
    #[serde(default)]
    pub(super) router_mesh_addr: Option<String>,
    #[serde(default)]
    pub(super) router_identity_id: Option<String>,
    #[serde(default)]
    pub(super) router_public_key_b64: Option<String>,
}
