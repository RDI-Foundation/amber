pub(crate) fn authorize_capability_instance<'a>(
    state: &'a FrameworkControlState,
    cap_instance_id: &str,
    peer_id: &str,
) -> std::result::Result<&'a CapabilityInstanceRecord, ProtocolErrorResponse> {
    let record = capability_instance_record(state, cap_instance_id)?;
    if record.recipient_peer_id != peer_id {
        return Err(protocol_error(
            ProtocolErrorCode::Unauthorized,
            "framework capability instance is not bound to the authenticated mesh peer",
        ));
    }
    Ok(record)
}

fn capability_instance_record<'a>(
    state: &'a FrameworkControlState,
    cap_instance_id: &str,
) -> std::result::Result<&'a CapabilityInstanceRecord, ProtocolErrorResponse> {
    state
        .capability_instances
        .get(cap_instance_id)
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::Unauthorized,
                "unknown framework capability instance",
            )
        })
}

fn scenario_component_checked(
    scenario: &Scenario,
    component_id: ComponentId,
) -> std::result::Result<&Component, ProtocolErrorResponse> {
    scenario
        .components
        .get(component_id.0)
        .and_then(Option::as_ref)
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &format!(
                    "framework authority realm {} is missing from the authoritative live graph",
                    component_id.0
                ),
            )
        })
}

pub(crate) fn list_templates(
    state: &FrameworkControlState,
    authority_realm_id: usize,
) -> std::result::Result<TemplateListResponse, ProtocolErrorResponse> {
    let scenario = decode_live_scenario(state)?;
    let component = scenario_component_checked(&scenario, ComponentId(authority_realm_id))?;
    Ok(TemplateListResponse {
        templates: component
            .child_templates
            .iter()
            .map(|(name, template)| TemplateSummary {
                name: name.clone(),
                mode: template_mode(template),
                possible_backends: template
                    .possible_backends
                    .iter()
                    .map(runtime_backend_name)
                    .collect(),
            })
            .collect(),
    })
}

pub(crate) fn describe_template(
    state: &FrameworkControlState,
    authority_realm_id: usize,
    template_name: &str,
) -> std::result::Result<TemplateDescribeResponse, ProtocolErrorResponse> {
    let scenario = decode_live_scenario(state)?;
    let scenario_ir = live_scenario_ir(state)?;
    let component = scenario_component_checked(&scenario, ComponentId(authority_realm_id))?;
    let template = component
        .child_templates
        .get(template_name)
        .ok_or_else(|| {
            protocol_error(ProtocolErrorCode::UnknownTemplate, "unknown child template")
        })?;
    let manifest = template_manifest_description(&scenario, template)?;
    let bindable_sources = bindable_source_candidates(
        &scenario,
        &scenario_ir,
        state,
        ComponentId(authority_realm_id),
    )?;
    let template_config = template_config_fields(template)?;
    let template_bindings = template_binding_fields(template)?;

    let config = template_config
        .iter()
        .map(|(name, field)| {
            (
                name.clone(),
                match field {
                    TemplateConfigField::Prefilled { value } => ConfigFieldDescription {
                        state: InputState::Prefilled,
                        value: Some(value.clone()),
                        required: None,
                    },
                    TemplateConfigField::Open { required } => ConfigFieldDescription {
                        state: InputState::Open,
                        value: None,
                        required: Some(*required),
                    },
                },
            )
        })
        .collect();

    let bindings = template_bindings
        .iter()
        .map(
            |(name, field)| -> std::result::Result<_, ProtocolErrorResponse> {
                Ok((
                    name.clone(),
                    match field {
                        TemplateBinding::Prefilled { selector } => BindingInputDescription {
                            state: InputState::Prefilled,
                            selector: Some(selector.to_string()),
                            optional: None,
                            compatible_kind: None,
                            candidates: Vec::new(),
                        },
                        TemplateBinding::Open { optional } => {
                            let slot_decl = root_template_slot_decl(template, name)?;
                            let candidates = bindable_sources
                                .iter()
                                .filter(|candidate| !candidate.sources.is_empty())
                                .filter(|candidate| {
                                    source_compatible(
                                        slot_decl.decl.clone(),
                                        candidate.decl.clone(),
                                    )
                                })
                                .map(|candidate| candidate.selector.clone())
                                .collect::<Vec<_>>();
                            BindingInputDescription {
                                state: InputState::Open,
                                selector: None,
                                optional: Some(*optional),
                                compatible_kind: Some(slot_decl.decl.kind.to_string()),
                                candidates,
                            }
                        }
                    },
                ))
            },
        )
        .collect::<std::result::Result<BTreeMap<_, _>, ProtocolErrorResponse>>()?;

    Ok(TemplateDescribeResponse {
        name: template_name.to_string(),
        manifest,
        config,
        bindings,
        exports: TemplateExportsDescription {
            visible: visible_exports(template)?,
        },
        limits: TemplateLimits {
            max_live_children: template
                .limits
                .as_ref()
                .and_then(|limits| limits.max_live_children.map(u64::from)),
        },
    })
}

pub(crate) fn list_children(
    state: &FrameworkControlState,
    authority_realm_id: usize,
) -> ChildListResponse {
    ChildListResponse {
        children: visible_child_records(state)
            .filter(|child| child.authority_realm_id == authority_realm_id)
            .map(|child| ChildSummary {
                name: child.name.clone(),
                state: child.state,
            })
            .collect(),
    }
}

pub(crate) fn describe_child(
    state: &FrameworkControlState,
    authority_realm_id: usize,
    child_name: &str,
) -> std::result::Result<ChildDescribeResponse, ProtocolErrorResponse> {
    let child = state
        .live_children
        .iter()
        .chain(state.pending_destroys.iter().map(|record| &record.child))
        .find(|child| child.authority_realm_id == authority_realm_id && child.name == child_name)
        .ok_or_else(|| protocol_error(ProtocolErrorCode::UnknownChild, "unknown child"))?;
    Ok(ChildDescribeResponse {
        name: child.name.clone(),
        state: child.state,
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
    })
}

pub(crate) fn snapshot(
    state: &FrameworkControlState,
    authority_realm_id: usize,
) -> std::result::Result<SnapshotResponse, ProtocolErrorResponse> {
    let scenario = decode_base_scenario(state)?;
    if authority_realm_id != scenario.root.0 {
        return Err(protocol_error(
            ProtocolErrorCode::ScopeNotAllowed,
            "snapshot is allowed only for the scenario root authority",
        ));
    }
    let mut live_scenario_ir = live_scenario_ir(state)?;
    let required_catalog_keys = live_scenario_ir
        .components
        .iter()
        .flat_map(|component| component.child_templates.values())
        .flat_map(|template| {
            template
                .manifest
                .iter()
                .cloned()
                .chain(template.allowed_manifests.clone().unwrap_or_default())
        })
        .collect::<BTreeSet<_>>();
    live_scenario_ir
        .manifest_catalog
        .retain(|key, _| required_catalog_keys.contains(key));
    normalize_scenario_ir_order(&mut live_scenario_ir);
    let mut assignments = state.placement.assignments.clone();
    for child in visible_child_records(state) {
        assignments.extend(child.assignments.clone());
    }
    Ok(SnapshotResponse {
        scenario: serde_json::to_value(&live_scenario_ir)
            .expect("live scenario snapshot should serialize"),
        placement: json!({
            "offered_sites": state.placement.offered_sites,
            "defaults": state.placement.defaults,
            "assignments": assignments,
        }),
    })
}

#[derive(Clone)]
struct ResolvedTemplateBinding {
    slot_name: String,
    slot_decl: amber_manifest::SlotDecl,
    sources: Vec<ResolvedBindingSource>,
    source_child_id: Option<u64>,
    dynamic_child_output: Option<DynamicChildOutputSource>,
}

#[derive(Clone)]
struct SyntheticSourceRecord {
    slot_name: String,
    actual_source: BindingFrom,
    source_child_id: Option<u64>,
    weak: bool,
}

#[derive(Clone)]
struct DynamicChildOutputSource {
    provider_component: String,
    provide: String,
    protocol: String,
    capability_kind: String,
    capability_profile: Option<String>,
}

