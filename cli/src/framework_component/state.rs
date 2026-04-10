use super::{http::*, orchestration::*, planner::*, *};

pub(super) const CONTROL_STATE_SCHEMA: &str = "amber.framework_component.control_state";
pub(super) const CONTROL_STATE_VERSION: u32 = 1;
pub(super) const CONTROL_SERVICE_PLAN_SCHEMA: &str =
    "amber.framework_component.control_service_plan";
pub(super) const CONTROL_SERVICE_PLAN_VERSION: u32 = 1;
pub(super) const CCS_PLAN_SCHEMA: &str = "amber.framework_component.ccs_plan";
pub(super) const CCS_PLAN_VERSION: u32 = 1;
pub(super) const CONTROL_SERVICE_PATH: &str = "/v1/control-state";
pub(super) const FRAMEWORK_ROUTE_ID_HEADER: &str = "x-amber-route-id";
pub(super) const FRAMEWORK_PEER_ID_HEADER: &str = "x-amber-peer-id";
pub(super) const FRAMEWORK_AUTH_HEADER: &str = "x-amber-framework-auth";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct FrozenPlacementState {
    pub(crate) offered_sites: BTreeMap<String, SiteDefinition>,
    pub(crate) defaults: PlacementDefaults,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) standby_sites: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) initial_active_sites: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) dynamic_enabled_sites: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) control_only_sites: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) active_site_capabilities: BTreeMap<String, ActiveSiteCapabilities>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) placement_components: BTreeMap<String, String>,
    pub(crate) assignments: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct CapabilityInstanceRecord {
    pub(crate) cap_instance_id: String,
    pub(crate) route_id: String,
    pub(crate) authority_realm_id: usize,
    pub(crate) authority_realm_moniker: String,
    pub(crate) recipient_component_id: usize,
    pub(crate) recipient_component_moniker: String,
    pub(crate) recipient_peer_id: String,
    pub(crate) recipient_site_id: String,
    pub(crate) capability: String,
    pub(crate) slot: String,
    pub(crate) generation: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LiveChildRecord {
    #[serde(default)]
    pub(crate) child_id: u64,
    pub(crate) authority_realm_id: usize,
    pub(crate) name: String,
    pub(crate) state: ChildState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) template_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) selected_manifest_catalog_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) fragment: Option<LiveScenarioFragment>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) input_bindings: Vec<ChildInputBindingRecord>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) assignments: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) site_plans: Vec<DynamicSitePlanRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) overlay_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) overlays: Vec<DynamicOverlayRecord>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) outputs: BTreeMap<String, OutputHandleRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PendingCreateRecord {
    pub(crate) tx_id: u64,
    pub(crate) child: LiveChildRecord,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PendingDestroyRecord {
    pub(crate) tx_id: u64,
    pub(crate) child: LiveChildRecord,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct DynamicSitePlanRecord {
    pub(crate) site_id: String,
    pub(crate) kind: SiteKind,
    pub(crate) router_identity_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) component_ids: Vec<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) assigned_components: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) artifact_files: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) desired_artifact_files: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) proxy_exports: BTreeMap<String, DynamicProxyExportRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) routed_inputs: Vec<DynamicInputRouteRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct DynamicProxyExportRecord {
    pub(crate) component_id: usize,
    pub(crate) component: String,
    pub(crate) provide: String,
    pub(crate) protocol: String,
    pub(crate) capability_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) capability_profile: Option<String>,
    pub(crate) target_port: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct DynamicInputRouteRecord {
    pub(crate) component: String,
    pub(crate) slot: String,
    pub(crate) provider_component: String,
    pub(crate) protocol: String,
    pub(crate) capability_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) capability_profile: Option<String>,
    #[serde(flatten)]
    pub(crate) target: DynamicInputRouteTarget,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "route_kind", rename_all = "snake_case")]
pub(crate) enum DynamicInputRouteTarget {
    ComponentProvide { provide: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum DynamicOverlayAction {
    ExternalSlot { link: RunLink },
    ExportPeer { link: RunLink },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct DynamicOverlayRecord {
    pub(crate) overlay_id: String,
    pub(crate) site_id: String,
    #[serde(flatten)]
    pub(crate) action: DynamicOverlayAction,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LiveScenarioFragment {
    pub(crate) root_component_id: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) components: Vec<ComponentIr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) bindings: Vec<LiveFragmentBindingRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LiveFragmentBindingRecord {
    pub(crate) binding: BindingIr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) source_child_id: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LiveBindingSourceRecord {
    pub(crate) from: BindingFromIr,
    #[serde(default)]
    pub(crate) weak: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct OutputHandleRecord {
    pub(crate) selector: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) handle: Option<String>,
    pub(crate) decl: CapabilityDecl,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) sources: Vec<LiveBindingSourceRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ChildInputBindingRecord {
    pub(crate) slot: String,
    pub(crate) decl: CapabilityDecl,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) sources: Vec<ChildInputBindingSourceRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ChildInputBindingSourceRecord {
    pub(crate) from: BindingFromIr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) component_moniker: Option<String>,
    #[serde(default)]
    pub(crate) weak: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ControlJournalEntry {
    pub(crate) tx_id: u64,
    pub(crate) child_id: u64,
    pub(crate) authority_realm_id: usize,
    pub(crate) child_name: String,
    pub(crate) state: ChildState,
    pub(crate) generation: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct FrameworkControlState {
    pub(crate) schema: String,
    pub(crate) version: u32,
    pub(crate) run_id: String,
    pub(crate) base_scenario: ScenarioIr,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) run_links: Vec<RunLink>,
    pub(crate) placement: FrozenPlacementState,
    #[serde(default)]
    pub(crate) generation: u64,
    #[serde(default)]
    pub(crate) next_child_id: u64,
    #[serde(default)]
    pub(crate) next_tx_id: u64,
    #[serde(default)]
    pub(crate) next_component_id: usize,
    #[serde(default)]
    pub(crate) capability_instances: BTreeMap<String, CapabilityInstanceRecord>,
    #[serde(default)]
    pub(crate) journal: Vec<ControlJournalEntry>,
    #[serde(default)]
    pub(crate) dynamic_capability_signing_seed_b64: String,
    #[serde(default)]
    pub(crate) next_dynamic_capability_grant_id: u64,
    #[serde(default)]
    pub(crate) dynamic_capability_grants: BTreeMap<String, dynamic_caps::DynamicGrantRecord>,
    #[serde(default)]
    pub(crate) dynamic_capability_journal: Vec<dynamic_caps::DynamicCapabilityJournalEntry>,
    #[serde(default)]
    pub(crate) live_children: Vec<LiveChildRecord>,
    #[serde(default)]
    pub(crate) pending_creates: Vec<PendingCreateRecord>,
    #[serde(default)]
    pub(crate) pending_destroys: Vec<PendingDestroyRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct FrameworkControlStateServicePlan {
    pub(crate) schema: String,
    pub(crate) version: u32,
    pub(crate) listen_addr: SocketAddr,
    pub(crate) state_path: String,
    pub(crate) run_root: String,
    pub(crate) state_root: String,
    pub(crate) mesh_scope: String,
    pub(crate) auth_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct FrameworkCcsPlan {
    pub(crate) schema: String,
    pub(crate) version: u32,
    pub(crate) site_id: String,
    pub(crate) site_state_root: String,
    pub(crate) listen_addr: SocketAddr,
    pub(crate) control_state_url: String,
    pub(crate) router_auth_token: String,
    pub(crate) control_state_auth_token: String,
}

pub(crate) fn build_control_state(
    run_id: &str,
    run_plan: &RunPlan,
) -> Result<FrameworkControlState> {
    let scenario = Scenario::try_from(run_plan.base_scenario.clone())
        .into_diagnostic()
        .map_err(|err| miette::miette!("failed to decode frozen base scenario: {err}"))?;
    let next_component_id = scenario
        .components_iter()
        .map(|(id, _)| id.0)
        .max()
        .map_or(0, |max_id| max_id + 1);

    let mut state = FrameworkControlState {
        schema: CONTROL_STATE_SCHEMA.to_string(),
        version: CONTROL_STATE_VERSION,
        run_id: run_id.to_string(),
        base_scenario: run_plan.base_scenario.clone(),
        run_links: run_plan.links.clone(),
        placement: FrozenPlacementState {
            offered_sites: run_plan.offered_sites.clone(),
            defaults: run_plan.defaults.clone(),
            standby_sites: run_plan.standby_sites.clone(),
            initial_active_sites: run_plan.initial_active_sites.clone(),
            dynamic_enabled_sites: run_plan.dynamic_enabled_sites.clone(),
            control_only_sites: run_plan.control_only_sites.clone(),
            active_site_capabilities: run_plan.active_site_capabilities.clone(),
            placement_components: run_plan.placement_components.clone(),
            assignments: run_plan.assignments.clone(),
        },
        generation: 0,
        next_child_id: 0,
        next_tx_id: 0,
        next_component_id,
        capability_instances: BTreeMap::new(),
        journal: Vec::new(),
        dynamic_capability_signing_seed_b64: amber_mesh::dynamic_caps::signing_seed_b64(
            &amber_mesh::dynamic_caps::signing_key_from_seed(
                amber_mesh::dynamic_caps::generate_dynamic_capability_signing_seed(),
            ),
        ),
        next_dynamic_capability_grant_id: 0,
        dynamic_capability_grants: BTreeMap::new(),
        dynamic_capability_journal: Vec::new(),
        live_children: Vec::new(),
        pending_creates: Vec::new(),
        pending_destroys: Vec::new(),
    };
    restore_framework_children_from_snapshot(&mut state, run_plan.framework_children.as_ref())?;
    refresh_capability_instances(&mut state)?;
    dynamic_caps::restore_dynamic_capabilities_from_snapshot(
        &mut state,
        run_plan.dynamic_capabilities.as_ref(),
    )
    .map_err(|err| miette::miette!(err.message.clone()))?;
    dynamic_caps::reconcile_dynamic_capability_grants(&mut state)
        .map_err(|err| miette::miette!(err.message.clone()))?;
    Ok(state)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct FrameworkChildSnapshotRecord {
    pub(super) child: FrameworkChildSnapshotState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) tx_id: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct FrameworkChildSnapshotState {
    pub(super) child_id: u64,
    pub(super) authority_realm_id: usize,
    pub(super) name: String,
    pub(super) state: ChildState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) template_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) selected_manifest_catalog_key: Option<String>,
    pub(super) fragment: LiveScenarioFragment,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) input_bindings: Vec<ChildInputBindingRecord>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) assignments: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) outputs: BTreeMap<String, OutputHandleRecord>,
}

pub(super) fn framework_child_snapshot_records_with_component_map(
    state: &FrameworkControlState,
    component_id_map: &BTreeMap<usize, usize>,
    monikers_by_component_id: &BTreeMap<usize, String>,
) -> std::result::Result<Vec<FrameworkChildSnapshotRecord>, ProtocolErrorResponse> {
    let mut snapshot_children = visible_child_records(state)
        .map(|child| {
            let remapped_authority = component_id_map
                .get(&child.authority_realm_id)
                .copied()
                .unwrap_or(child.authority_realm_id);
            let authority_moniker = monikers_by_component_id
                .get(&remapped_authority)
                .cloned()
                .or_else(|| authority_moniker_for_child(state, child))
                .ok_or_else(|| {
                    protocol_error(
                        ProtocolErrorCode::ControlStateUnavailable,
                        &format!(
                            "dynamic child `{}` references missing authority realm {}",
                            child.name, child.authority_realm_id
                        ),
                    )
                })?;
            Ok((authority_moniker, child.clone()))
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    snapshot_children.sort_by(
        |(left_authority, left_child), (right_authority, right_child)| {
            left_authority
                .cmp(right_authority)
                .then(left_child.name.cmp(&right_child.name))
                .then(
                    child_state_snapshot_sort_key(left_child.state)
                        .cmp(&child_state_snapshot_sort_key(right_child.state)),
                )
                .then(left_child.child_id.cmp(&right_child.child_id))
        },
    );

    let child_id_map = snapshot_children
        .iter()
        .enumerate()
        .map(|(index, (_, child))| (child.child_id, index as u64 + 1))
        .collect::<BTreeMap<_, _>>();
    let tx_id_map = snapshot_children
        .iter()
        .filter(|(_, child)| child.state == ChildState::DestroyRequested)
        .enumerate()
        .map(|(index, (_, child))| (child.child_id, index as u64 + 1))
        .collect::<BTreeMap<_, _>>();

    snapshot_children
        .into_iter()
        .map(|(_, child)| {
            let child_id = *child_id_map.get(&child.child_id).ok_or_else(|| {
                protocol_error(
                    ProtocolErrorCode::ControlStateUnavailable,
                    &format!(
                        "dynamic child `{}` is missing from snapshot id normalization",
                        child.name
                    ),
                )
            })?;
            let authority_realm_id = remap_component_id(
                child.authority_realm_id,
                component_id_map,
                &format!("snapshot authority realm for child `{}`", child.name),
            )?;
            let fragment = remap_live_fragment_for_snapshot(
                child.fragment.as_ref().ok_or_else(|| {
                    protocol_error(
                        ProtocolErrorCode::ControlStateUnavailable,
                        &format!(
                            "dynamic child `{}` is missing the live fragment required for snapshot",
                            child.name
                        ),
                    )
                })?,
                component_id_map,
                &child_id_map,
                monikers_by_component_id,
            )?;
            let outputs = child
                .outputs
                .iter()
                .map(|(output_name, output)| {
                    Ok((
                        output_name.clone(),
                        remap_output_handle_for_snapshot(
                            output_name,
                            &child.name,
                            child_id,
                            output,
                            component_id_map,
                        )?,
                    ))
                })
                .collect::<std::result::Result<BTreeMap<_, _>, _>>()?;
            let input_bindings = child
                .input_bindings
                .iter()
                .cloned()
                .map(|mut input_binding| {
                    input_binding.sources = input_binding
                        .sources
                        .into_iter()
                        .map(|mut source| {
                            remap_binding_source_for_snapshot(
                                &mut source.from,
                                component_id_map,
                                "snapshot child input binding source",
                            )?;
                            Ok(source)
                        })
                        .collect::<std::result::Result<Vec<_>, ProtocolErrorResponse>>()?;
                    Ok(input_binding)
                })
                .collect::<std::result::Result<Vec<_>, ProtocolErrorResponse>>()?;
            Ok(FrameworkChildSnapshotRecord {
                tx_id: (child.state == ChildState::DestroyRequested).then(|| {
                    *tx_id_map.get(&child.child_id).expect(
                        "destroy-requested snapshot child should keep a normalized transaction",
                    )
                }),
                child: FrameworkChildSnapshotState {
                    child_id,
                    authority_realm_id,
                    name: child.name,
                    state: child.state,
                    template_name: child.template_name,
                    selected_manifest_catalog_key: child.selected_manifest_catalog_key,
                    fragment,
                    input_bindings,
                    assignments: child.assignments,
                    outputs,
                },
            })
        })
        .collect()
}

pub(super) fn restore_framework_children_from_snapshot(
    state: &mut FrameworkControlState,
    snapshot: Option<&serde_json::Value>,
) -> Result<()> {
    let Some(snapshot) = snapshot else {
        return Ok(());
    };
    if snapshot.is_null() {
        return Ok(());
    }
    let records: Vec<FrameworkChildSnapshotRecord> = serde_json::from_value(snapshot.clone())
        .into_diagnostic()
        .map_err(|err| miette::miette!("failed to decode framework child snapshot: {err}"))?;
    let scenario = decode_base_scenario(state).map_err(|err| miette::miette!(err.message))?;
    let mut snapshot_assignments = state.placement.assignments.clone();
    for record in &records {
        snapshot_assignments.extend(record.child.assignments.clone());
    }
    for record in records {
        let FrameworkChildSnapshotRecord { child, tx_id } = record;
        let mut child = LiveChildRecord {
            child_id: child.child_id,
            authority_realm_id: child.authority_realm_id,
            name: child.name,
            state: child.state,
            template_name: child.template_name,
            selected_manifest_catalog_key: child.selected_manifest_catalog_key,
            fragment: Some(child.fragment),
            input_bindings: child.input_bindings,
            assignments: child.assignments,
            site_plans: Vec::new(),
            overlay_ids: Vec::new(),
            overlays: Vec::new(),
            outputs: child.outputs,
        };
        rebuild_live_child_runtime_metadata(state, &scenario, &snapshot_assignments, &mut child)
            .map_err(|err| miette::miette!(err.message))?;
        state.next_child_id = state.next_child_id.max(child.child_id);
        match child.state {
            ChildState::Live => state.live_children.push(child),
            ChildState::DestroyRequested => {
                let tx_id = tx_id.ok_or_else(|| {
                    miette::miette!(
                        "framework child snapshot is missing a transaction for child `{}`",
                        child.name
                    )
                })?;
                state.next_tx_id = state.next_tx_id.max(tx_id);
                state
                    .pending_destroys
                    .push(PendingDestroyRecord { tx_id, child });
            }
            state => {
                return Err(miette::miette!(
                    "framework child snapshot contains unsupported child state `{state:?}`"
                ));
            }
        }
    }
    Ok(())
}

fn child_state_snapshot_sort_key(state: ChildState) -> u8 {
    match state {
        ChildState::Live => 0,
        ChildState::DestroyRequested => 1,
        ChildState::CreateRequested => 2,
        ChildState::CreatePrepared => 3,
        ChildState::CreateCommittedHidden => 4,
        ChildState::CreateAborted => 5,
        ChildState::DestroyRetracted => 6,
        ChildState::DestroyCommitted => 7,
    }
}

fn authority_moniker_for_child(
    state: &FrameworkControlState,
    child: &LiveChildRecord,
) -> Option<String> {
    child
        .fragment
        .as_ref()
        .and_then(|fragment| {
            fragment
                .components
                .iter()
                .find(|component| component.id == fragment.root_component_id)
                .and_then(|component| authority_moniker_for_root(component.moniker.as_str()))
        })
        .or_else(|| {
            state
                .base_scenario
                .components
                .iter()
                .find(|component| component.id == child.authority_realm_id)
                .map(|component| component.moniker.clone())
        })
}

fn authority_moniker_for_root(moniker: &str) -> Option<String> {
    if moniker == "/" {
        return None;
    }
    let (parent, _) = moniker.rsplit_once('/')?;
    Some(if parent.is_empty() {
        "/".to_string()
    } else {
        parent.to_string()
    })
}

fn remap_component_id(
    component_id: usize,
    component_id_map: &BTreeMap<usize, usize>,
    context: &str,
) -> std::result::Result<usize, ProtocolErrorResponse> {
    component_id_map.get(&component_id).copied().ok_or_else(|| {
        protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &format!("{context} references missing component id {component_id}"),
        )
    })
}

fn remap_binding_source_for_snapshot(
    source: &mut BindingFromIr,
    component_id_map: &BTreeMap<usize, usize>,
    context: &str,
) -> std::result::Result<(), ProtocolErrorResponse> {
    match source {
        BindingFromIr::Component { component, .. } | BindingFromIr::Resource { component, .. } => {
            *component = remap_component_id(*component, component_id_map, context)?;
        }
        BindingFromIr::Framework {
            authority_realm, ..
        } => {
            *authority_realm = remap_component_id(*authority_realm, component_id_map, context)?;
        }
        BindingFromIr::External { slot } => {
            slot.component = remap_component_id(slot.component, component_id_map, context)?;
        }
    }
    Ok(())
}

fn remap_binding_for_snapshot(
    binding: &mut BindingIr,
    component_id_map: &BTreeMap<usize, usize>,
    context: &str,
) -> std::result::Result<(), ProtocolErrorResponse> {
    remap_binding_source_for_snapshot(&mut binding.from, component_id_map, context)?;
    binding.to.component = remap_component_id(binding.to.component, component_id_map, context)?;
    Ok(())
}

fn remap_live_fragment_for_snapshot(
    fragment: &LiveScenarioFragment,
    component_id_map: &BTreeMap<usize, usize>,
    child_id_map: &BTreeMap<u64, u64>,
    monikers_by_component_id: &BTreeMap<usize, String>,
) -> std::result::Result<LiveScenarioFragment, ProtocolErrorResponse> {
    let mut components = fragment
        .components
        .iter()
        .cloned()
        .map(|mut component| {
            component.id = remap_component_id(
                component.id,
                component_id_map,
                "snapshot child fragment component",
            )?;
            component.parent = component
                .parent
                .map(|parent| {
                    remap_component_id(parent, component_id_map, "snapshot child fragment parent")
                })
                .transpose()?;
            for child in &mut component.children {
                *child =
                    remap_component_id(*child, component_id_map, "snapshot child fragment edge")?;
            }
            Ok(component)
        })
        .collect::<std::result::Result<Vec<_>, ProtocolErrorResponse>>()?;
    components.sort_by(|left, right| {
        left.moniker
            .cmp(&right.moniker)
            .then(left.id.cmp(&right.id))
    });
    for component in &mut components {
        component.children.sort_by(|left, right| {
            let left_moniker = monikers_by_component_id
                .get(left)
                .map(String::as_str)
                .unwrap_or("/");
            let right_moniker = monikers_by_component_id
                .get(right)
                .map(String::as_str)
                .unwrap_or("/");
            left_moniker.cmp(right_moniker)
        });
    }

    let mut bindings = fragment
        .bindings
        .iter()
        .cloned()
        .map(|mut binding| {
            remap_binding_for_snapshot(
                &mut binding.binding,
                component_id_map,
                "snapshot child binding",
            )?;
            binding.source_child_id = binding
                .source_child_id
                .map(|source_child_id| {
                    child_id_map.get(&source_child_id).copied().ok_or_else(|| {
                        protocol_error(
                            ProtocolErrorCode::ControlStateUnavailable,
                            &format!(
                                "snapshot child binding references missing source child id \
                                 {source_child_id}"
                            ),
                        )
                    })
                })
                .transpose()?;
            Ok(binding)
        })
        .collect::<std::result::Result<Vec<_>, ProtocolErrorResponse>>()?;
    bindings.sort_by(|left, right| {
        binding_sort_key(&left.binding, monikers_by_component_id)
            .cmp(&binding_sort_key(&right.binding, monikers_by_component_id))
    });

    Ok(LiveScenarioFragment {
        root_component_id: remap_component_id(
            fragment.root_component_id,
            component_id_map,
            "snapshot child root component",
        )?,
        components,
        bindings,
    })
}

fn remap_output_handle_for_snapshot(
    output_name: &str,
    child_name: &str,
    child_id: u64,
    output: &OutputHandleRecord,
    component_id_map: &BTreeMap<usize, usize>,
) -> std::result::Result<OutputHandleRecord, ProtocolErrorResponse> {
    let sources = output
        .sources
        .iter()
        .cloned()
        .map(|mut source| {
            remap_binding_source_for_snapshot(
                &mut source.from,
                component_id_map,
                "snapshot child output source",
            )?;
            Ok(source)
        })
        .collect::<std::result::Result<Vec<_>, ProtocolErrorResponse>>()?;
    Ok(OutputHandleRecord {
        selector: format!("children.{child_name}.exports.{output_name}"),
        handle: output
            .handle
            .as_ref()
            .map(|_| format!("h_{child_id}_{output_name}")),
        decl: output.decl.clone(),
        sources,
    })
}

pub(crate) fn generate_framework_auth_token(mesh_scope: &str, purpose: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(
        MeshIdentity::generate(
            format!("/framework/{purpose}"),
            Some(mesh_scope.to_string()),
        )
        .public_key,
    )
}

pub(crate) fn control_state_service_url(listen_addr: SocketAddr) -> String {
    format!("http://{listen_addr}")
}

pub(crate) fn ccs_listen_addr_for_site(kind: SiteKind, port: u16) -> SocketAddr {
    host_service_bind_addr_for_consumer(kind, port)
}

pub(crate) fn ccs_url_for_site(kind: SiteKind, port: u16) -> String {
    let host = match kind {
        SiteKind::Direct | SiteKind::Vm => Ipv4Addr::LOCALHOST.to_string(),
        SiteKind::Compose | SiteKind::Kubernetes => host_service_host_for_consumer(kind),
    };
    format!("http://{host}:{port}")
}

pub(crate) fn write_control_state(path: &Path, state: &FrameworkControlState) -> Result<()> {
    write_json(path, state)
}

pub(super) fn persist_control_state(path: &Path, state: &mut FrameworkControlState) -> Result<()> {
    refresh_capability_instances(state)?;
    dynamic_caps::reconcile_dynamic_capability_grants(state)
        .map_err(|err| miette::miette!(err.message.clone()))?;
    write_control_state(path, state)
}

pub(super) fn persist_control_state_update<T>(
    state: &mut FrameworkControlState,
    path: &Path,
    step: &str,
    update: impl FnOnce(&mut FrameworkControlState) -> std::result::Result<T, ProtocolErrorResponse>,
) -> std::result::Result<T, ProtocolErrorResponse> {
    let snapshot = state.clone();
    let result = match update(state) {
        Ok(result) => result,
        Err(err) => {
            *state = snapshot;
            return Err(err);
        }
    };
    if let Err(err) = persist_control_state(path, state) {
        *state = snapshot;
        return Err(control_state_step_error(step, err));
    }
    Ok(result)
}

#[derive(Clone, Copy)]
pub(super) enum ChildRecordLocation {
    Live(usize),
    PendingCreate(usize),
    PendingDestroy(usize),
}

pub(super) fn all_child_records(
    state: &FrameworkControlState,
) -> impl Iterator<Item = &LiveChildRecord> {
    state
        .live_children
        .iter()
        .chain(state.pending_creates.iter().map(|record| &record.child))
        .chain(state.pending_destroys.iter().map(|record| &record.child))
}

pub(super) fn visible_child_records(
    state: &FrameworkControlState,
) -> impl Iterator<Item = &LiveChildRecord> {
    state
        .live_children
        .iter()
        .chain(state.pending_destroys.iter().map(|record| &record.child))
        .filter(|child| child_is_visible(child))
}

pub(super) fn child_record_location(
    state: &FrameworkControlState,
    child_id: u64,
) -> std::result::Result<ChildRecordLocation, ProtocolErrorResponse> {
    if let Some(index) = state
        .live_children
        .iter()
        .position(|child| child.child_id == child_id)
    {
        return Ok(ChildRecordLocation::Live(index));
    }
    if let Some(index) = state
        .pending_creates
        .iter()
        .position(|record| record.child.child_id == child_id)
    {
        return Ok(ChildRecordLocation::PendingCreate(index));
    }
    if let Some(index) = state
        .pending_destroys
        .iter()
        .position(|record| record.child.child_id == child_id)
    {
        return Ok(ChildRecordLocation::PendingDestroy(index));
    }
    Err(protocol_error(
        ProtocolErrorCode::ControlStateUnavailable,
        &format!("child id {child_id} is missing from authoritative state"),
    ))
}

pub(super) fn child_record_mut(
    state: &mut FrameworkControlState,
    child_id: u64,
) -> std::result::Result<&mut LiveChildRecord, ProtocolErrorResponse> {
    match child_record_location(state, child_id)? {
        ChildRecordLocation::Live(index) => Ok(&mut state.live_children[index]),
        ChildRecordLocation::PendingCreate(index) => Ok(&mut state.pending_creates[index].child),
        ChildRecordLocation::PendingDestroy(index) => Ok(&mut state.pending_destroys[index].child),
    }
}

pub(super) fn child_create_tx_id(
    state: &FrameworkControlState,
    child_id: u64,
) -> std::result::Result<u64, ProtocolErrorResponse> {
    state
        .pending_creates
        .iter()
        .find(|record| record.child.child_id == child_id)
        .map(|record| record.tx_id)
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &format!("child id {child_id} is missing pending create transaction state"),
            )
        })
}

pub(super) fn child_destroy_tx_id(
    state: &FrameworkControlState,
    child_id: u64,
) -> std::result::Result<u64, ProtocolErrorResponse> {
    state
        .pending_destroys
        .iter()
        .find(|record| record.child.child_id == child_id)
        .map(|record| record.tx_id)
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &format!("child id {child_id} is missing pending destroy transaction state"),
            )
        })
}

pub(crate) fn write_control_state_service_plan(
    path: &Path,
    listen_addr: SocketAddr,
    state_path: &Path,
    run_root: &Path,
    state_root: &Path,
    mesh_scope: &str,
    auth_token: &str,
) -> Result<FrameworkControlStateServicePlan> {
    let plan = FrameworkControlStateServicePlan {
        schema: CONTROL_SERVICE_PLAN_SCHEMA.to_string(),
        version: CONTROL_SERVICE_PLAN_VERSION,
        listen_addr,
        state_path: state_path.display().to_string(),
        run_root: run_root.display().to_string(),
        state_root: state_root.display().to_string(),
        mesh_scope: mesh_scope.to_string(),
        auth_token: auth_token.to_string(),
    };
    write_json(path, &plan)?;
    Ok(plan)
}

pub(crate) fn write_framework_ccs_plan(
    path: &Path,
    site_id: &str,
    site_state_root: &Path,
    listen_addr: SocketAddr,
    control_state_url: &str,
    router_auth_token: &str,
    control_state_auth_token: &str,
) -> Result<FrameworkCcsPlan> {
    let plan = FrameworkCcsPlan {
        schema: CCS_PLAN_SCHEMA.to_string(),
        version: CCS_PLAN_VERSION,
        site_id: site_id.to_string(),
        site_state_root: site_state_root.display().to_string(),
        listen_addr,
        control_state_url: control_state_url.to_string(),
        router_auth_token: router_auth_token.to_string(),
        control_state_auth_token: control_state_auth_token.to_string(),
    };
    write_json(path, &plan)?;
    Ok(plan)
}
