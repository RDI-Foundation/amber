use super::{http::*, orchestration::*, planner::*, *};

pub(super) const CONTROL_STATE_SCHEMA: &str = "amber.framework_component.control_state";
pub(super) const CONTROL_STATE_VERSION: u32 = 1;
pub(super) const SITE_CONTROLLER_PLAN_SCHEMA: &str =
    "amber.framework_component.site_controller_plan";
pub(super) const SITE_CONTROLLER_PLAN_VERSION: u32 = 1;
pub(super) const SITE_CONTROLLER_STATE_PATH: &str = "/v1/controller/state";
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
pub struct DynamicSitePlanRecord {
    pub site_id: String,
    pub kind: SiteKind,
    pub router_identity_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub component_ids: Vec<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assigned_components: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub artifact_files: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub desired_artifact_files: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub proxy_exports: BTreeMap<String, DynamicProxyExportRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routed_inputs: Vec<DynamicInputRouteRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DynamicProxyExportRecord {
    pub component_id: usize,
    pub component: String,
    pub provide: String,
    pub protocol: String,
    pub capability_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_profile: Option<String>,
    pub target_port: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DynamicInputRouteRecord {
    pub component: String,
    pub slot: String,
    pub provider_component: String,
    pub protocol: String,
    pub capability_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_profile: Option<String>,
    #[serde(flatten)]
    pub target: DynamicInputRouteTarget,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "route_kind", rename_all = "snake_case")]
pub enum DynamicInputRouteTarget {
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
pub struct FrameworkControlState {
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
    #[serde(default = "default_framework_id_stride")]
    pub(crate) id_stride: u64,
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

fn default_framework_id_stride() -> u64 {
    1
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SiteControllerPeerPlan {
    pub site_id: String,
    pub kind: SiteKind,
    pub authority_url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SiteControllerPlan {
    pub schema: String,
    pub version: u32,
    pub run_id: String,
    pub mesh_scope: String,
    pub site_id: String,
    pub kind: SiteKind,
    pub listen_addr: SocketAddr,
    pub authority_url: String,
    pub router_identity_id: String,
    pub state_path: String,
    pub run_root: String,
    pub state_root: String,
    pub site_state_root: String,
    pub artifact_dir: String,
    pub auth_token: String,
    pub dynamic_caps_token_verify_key_b64: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub peer_controllers: BTreeMap<String, SiteControllerPeerPlan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router_mesh_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compose_project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes_namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observability_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub launch_env: BTreeMap<String, String>,
}

#[cfg(test)]
pub(crate) fn build_control_state(
    run_id: &str,
    run_plan: &RunPlan,
) -> Result<FrameworkControlState> {
    build_control_state_with_signing_seed(
        run_id,
        run_plan,
        &amber_mesh::dynamic_caps::signing_seed_b64(
            &amber_mesh::dynamic_caps::signing_key_from_seed(
                amber_mesh::dynamic_caps::generate_dynamic_capability_signing_seed(),
            ),
        ),
    )
}

pub fn build_site_controller_state(
    run_id: &str,
    run_plan: &RunPlan,
    site_id: &str,
    site_index: usize,
    site_count: usize,
    dynamic_capability_signing_seed_b64: &str,
) -> Result<FrameworkControlState> {
    let mut state = build_control_state_with_signing_seed(
        run_id,
        run_plan,
        dynamic_capability_signing_seed_b64,
    )?;
    localize_framework_control_state(&mut state, site_id)?;
    let site_offset = site_index as u64;
    let id_stride = site_count.max(1) as u64;
    state.next_child_id = localized_last_allocated_counter(
        site_offset,
        id_stride,
        state
            .live_children
            .iter()
            .map(|child| child.child_id)
            .chain(
                state
                    .pending_creates
                    .iter()
                    .map(|record| record.child.child_id),
            )
            .chain(
                state
                    .pending_destroys
                    .iter()
                    .map(|record| record.child.child_id),
            ),
    );
    state.next_tx_id = localized_last_allocated_counter(
        site_offset,
        id_stride,
        state
            .pending_creates
            .iter()
            .map(|record| record.tx_id)
            .chain(state.pending_destroys.iter().map(|record| record.tx_id))
            .chain(state.journal.iter().map(|entry| entry.tx_id)),
    );
    state.next_dynamic_capability_grant_id = localized_next_available_counter(
        site_offset,
        id_stride,
        state
            .dynamic_capability_grants
            .keys()
            .filter_map(|grant_id| dynamic_capability_grant_counter(grant_id))
            .chain(
                state
                    .dynamic_capability_journal
                    .iter()
                    .filter_map(|entry| entry.grant_id.as_deref())
                    .filter_map(dynamic_capability_grant_counter),
            ),
    );
    state.id_stride = id_stride;
    Ok(state)
}

fn localized_last_allocated_counter(
    site_offset: u64,
    id_stride: u64,
    used_ids: impl Iterator<Item = u64>,
) -> u64 {
    let max_used_id = used_ids.max();
    match max_used_id {
        Some(max_used_id) if max_used_id > site_offset => {
            site_offset + ((max_used_id - site_offset) / id_stride.max(1)) * id_stride.max(1)
        }
        _ => site_offset,
    }
}

fn localized_next_available_counter(
    site_offset: u64,
    id_stride: u64,
    used_ids: impl Iterator<Item = u64>,
) -> u64 {
    let max_used_id = used_ids.max();
    match max_used_id {
        Some(max_used_id) if max_used_id >= site_offset => {
            site_offset + (((max_used_id - site_offset) / id_stride.max(1)) + 1) * id_stride.max(1)
        }
        _ => site_offset,
    }
}

fn dynamic_capability_grant_counter(grant_id: &str) -> Option<u64> {
    grant_id
        .strip_prefix(dynamic_caps::DYNAMIC_CAPABILITY_GRANT_ID_PREFIX)
        .and_then(|suffix| u64::from_str_radix(suffix, 16).ok())
}

fn build_control_state_with_signing_seed(
    run_id: &str,
    run_plan: &RunPlan,
    dynamic_capability_signing_seed_b64: &str,
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
        id_stride: default_framework_id_stride(),
        next_component_id,
        capability_instances: BTreeMap::new(),
        journal: Vec::new(),
        dynamic_capability_signing_seed_b64: dynamic_capability_signing_seed_b64.to_string(),
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

pub(crate) fn localize_framework_control_state(
    state: &mut FrameworkControlState,
    site_id: &str,
) -> Result<()> {
    let local_child_ids = state
        .live_children
        .iter()
        .chain(state.pending_creates.iter().map(|record| &record.child))
        .chain(state.pending_destroys.iter().map(|record| &record.child))
        .filter_map(|child| {
            child_authority_site_id(state, child)
                .ok()
                .filter(|authority_site_id| authority_site_id == site_id)
                .map(|_| child.child_id)
        })
        .collect::<BTreeSet<_>>();
    state
        .live_children
        .retain(|child| local_child_ids.contains(&child.child_id));
    state
        .pending_creates
        .retain(|record| local_child_ids.contains(&record.child.child_id));
    state
        .pending_destroys
        .retain(|record| local_child_ids.contains(&record.child.child_id));
    state
        .journal
        .retain(|entry| local_child_ids.contains(&entry.child_id));

    let roots = dynamic_caps::derive_root_authorities(state)
        .map_err(|err| miette::miette!(err.message.clone()))?;
    let local_grant_ids = state
        .dynamic_capability_grants
        .iter()
        .filter_map(|(grant_id, grant)| {
            roots
                .get(&dynamic_caps::root_authority_key(
                    &grant.root_authority_selector,
                ))
                .and_then(|root| component_site_id(state, &root.holder_component_id).ok())
                .filter(|root_site_id| root_site_id == site_id)
                .map(|_| grant_id.clone())
        })
        .collect::<BTreeSet<_>>();
    state
        .dynamic_capability_grants
        .retain(|grant_id, _| local_grant_ids.contains(grant_id));
    state.dynamic_capability_journal.retain(|entry| {
        entry
            .grant_id
            .as_ref()
            .is_none_or(|grant_id| local_grant_ids.contains(grant_id))
    });
    Ok(())
}

fn child_authority_site_id(
    state: &FrameworkControlState,
    child: &LiveChildRecord,
) -> std::result::Result<String, ProtocolErrorResponse> {
    let authority_moniker = decode_live_scenario(state)?
        .component(ComponentId(child.authority_realm_id))
        .moniker
        .to_string();
    site_id_for_moniker(
        state,
        &authority_moniker,
        &format!("authority realm `{authority_moniker}`"),
    )
}

fn component_site_id(
    state: &FrameworkControlState,
    logical_component_id: &str,
) -> std::result::Result<String, ProtocolErrorResponse> {
    let moniker = dynamic_caps::moniker_from_logical_component_id(logical_component_id)?;
    let moniker = moniker.to_string();
    site_id_for_moniker(
        state,
        &moniker,
        &format!("component `{logical_component_id}`"),
    )
}

fn site_id_for_moniker(
    state: &FrameworkControlState,
    moniker: &str,
    subject: &str,
) -> std::result::Result<String, ProtocolErrorResponse> {
    let assignments = live_assignment_map(state);
    if let Some(site_id) = assignments.get(moniker) {
        return Ok(site_id.clone());
    }

    let descendant_sites = assignments
        .iter()
        .filter(|(assigned_moniker, _)| moniker_contains(assigned_moniker, moniker))
        .map(|(_, site_id)| site_id.clone())
        .collect::<BTreeSet<_>>();
    if descendant_sites.len() == 1 {
        return Ok(descendant_sites
            .into_iter()
            .next()
            .expect("single descendant site should be present"));
    }

    Err(protocol_error(
        ProtocolErrorCode::ControlStateUnavailable,
        &if descendant_sites.is_empty() {
            format!("{subject} is missing a site assignment")
        } else {
            format!(
                "{subject} is missing a site assignment and spans multiple sites: {}",
                descendant_sites.into_iter().collect::<Vec<_>>().join(", ")
            )
        },
    ))
}

fn moniker_contains(candidate: &str, realm: &str) -> bool {
    if realm == "/" {
        return true;
    }
    candidate
        .strip_prefix(realm)
        .is_some_and(|suffix| suffix.starts_with('/'))
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

pub fn generate_framework_auth_token(mesh_scope: &str, purpose: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(
        MeshIdentity::generate(
            format!("/framework/{purpose}"),
            Some(mesh_scope.to_string()),
        )
        .public_key,
    )
}

pub fn authority_url_for_listen_addr(listen_addr: SocketAddr) -> String {
    let dial_addr = if listen_addr.ip().is_unspecified() {
        SocketAddr::from(([127, 0, 0, 1], listen_addr.port()))
    } else {
        listen_addr
    };
    format!("http://{dial_addr}")
}

pub fn write_control_state(path: &Path, state: &FrameworkControlState) -> Result<()> {
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

#[allow(clippy::too_many_arguments)]
pub fn write_site_controller_plan(
    path: &Path,
    run_id: &str,
    mesh_scope: &str,
    site_id: &str,
    kind: SiteKind,
    listen_addr: SocketAddr,
    authority_url: &str,
    router_identity_id: &str,
    state_path: &Path,
    run_root: &Path,
    state_root: &Path,
    site_state_root: &Path,
    artifact_dir: &Path,
    auth_token: &str,
    dynamic_caps_token_verify_key_b64: &str,
    peer_controllers: BTreeMap<String, SiteControllerPeerPlan>,
    storage_root: Option<&str>,
    runtime_root: Option<&str>,
    router_mesh_port: Option<u16>,
    compose_project: Option<&str>,
    kubernetes_namespace: Option<&str>,
    context: Option<&str>,
    observability_endpoint: Option<&str>,
    launch_env: &BTreeMap<String, String>,
) -> Result<SiteControllerPlan> {
    let plan = SiteControllerPlan {
        schema: SITE_CONTROLLER_PLAN_SCHEMA.to_string(),
        version: SITE_CONTROLLER_PLAN_VERSION,
        run_id: run_id.to_string(),
        mesh_scope: mesh_scope.to_string(),
        site_id: site_id.to_string(),
        kind,
        listen_addr,
        authority_url: authority_url.to_string(),
        router_identity_id: router_identity_id.to_string(),
        state_path: state_path.display().to_string(),
        run_root: run_root.display().to_string(),
        state_root: state_root.display().to_string(),
        site_state_root: site_state_root.display().to_string(),
        artifact_dir: artifact_dir.display().to_string(),
        auth_token: auth_token.to_string(),
        dynamic_caps_token_verify_key_b64: dynamic_caps_token_verify_key_b64.to_string(),
        peer_controllers,
        storage_root: storage_root.map(str::to_string),
        runtime_root: runtime_root.map(str::to_string),
        router_mesh_port,
        compose_project: compose_project.map(str::to_string),
        kubernetes_namespace: kubernetes_namespace.map(str::to_string),
        context: context.map(str::to_string),
        observability_endpoint: observability_endpoint.map(str::to_string),
        launch_env: launch_env.clone(),
    };
    write_json(path, &plan)?;
    Ok(plan)
}

pub(crate) fn site_id_for_authority_realm(
    state: &FrameworkControlState,
    authority_realm_id: usize,
) -> std::result::Result<String, ProtocolErrorResponse> {
    let authority_moniker = decode_live_scenario(state)?
        .component(ComponentId(authority_realm_id))
        .moniker
        .to_string();
    site_id_for_moniker(
        state,
        authority_moniker.as_str(),
        &format!("authority realm `{authority_moniker}`"),
    )
}

pub(crate) fn site_id_for_dynamic_grant(
    state: &FrameworkControlState,
    grant_id: &str,
) -> std::result::Result<String, ProtocolErrorResponse> {
    let grant = state
        .dynamic_capability_grants
        .get(grant_id)
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::UnknownSource,
                &format!("dynamic grant `{grant_id}` is not live"),
            )
        })?;
    site_id_for_logical_component(state, &grant.holder_component_id).map_err(|_| {
        protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &format!(
                "dynamic grant `{grant_id}` holder `{}` is missing a live site assignment",
                grant.holder_component_id
            ),
        )
    })
}

pub(crate) fn site_id_for_logical_component(
    state: &FrameworkControlState,
    logical_component_id: &str,
) -> std::result::Result<String, ProtocolErrorResponse> {
    component_site_id(state, logical_component_id)
}

pub(crate) fn site_id_for_root_authority_selector(
    state: &FrameworkControlState,
    selector: &RootAuthoritySelectorIr,
) -> std::result::Result<String, ProtocolErrorResponse> {
    let roots = dynamic_caps::derive_root_authorities(state)?;
    let root = roots
        .get(&dynamic_caps::root_authority_key(selector))
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::UnknownSource,
                "dynamic capability root authority is not live",
            )
        })?;
    site_id_for_logical_component(state, &root.holder_component_id)
}
