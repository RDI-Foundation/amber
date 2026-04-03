use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    future::Future,
    io::Write as _,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use amber_compiler::{
    CompileOptions, Compiler, DigestStore,
    reporter::CompiledScenario,
    run_plan::{
        PlacementDefaults, PlacementFile, RunLink, RunPlan, SiteDefinition, SiteKind,
        build_run_plan,
    },
};
use amber_manifest::{
    CapabilityDecl, CapabilityTransport, ComponentDecl, ComponentRef, FrameworkCapabilityName,
    Manifest, ManifestRef, ManifestSpans, NetworkProtocol, RawBinding, RawExportTarget, SlotDecl,
};
use amber_mesh::{
    MeshProtocol,
    component_protocol::{
        BindingInputDescription, ChildDescribeResponse, ChildHandle, ChildListResponse, ChildState,
        ChildSummary, ConfigFieldDescription, CreateChildRequest, CreateChildResponse, InputState,
        ProtocolErrorCode, ProtocolErrorResponse, SnapshotResponse, TemplateDescribeResponse,
        TemplateExportsDescription, TemplateLimits, TemplateListResponse,
        TemplateManifestDescription, TemplateMode, TemplateSummary,
    },
    framework_cap_instance_id, router_dynamic_export_route_id, router_export_route_id,
};
use amber_proxy::{
    clear_external_slot_with_retry, register_export_peer_with_retry,
    register_external_slot_with_retry, unregister_export_peer_with_retry,
};
use amber_resolver::{Backend, RemoteResolver, Resolution, Resolver};
use amber_scenario::{
    BindingFrom, ChildTemplate, Component, ComponentId, FrameworkRef, ProvideRef, ResourceRef,
    Scenario, ScenarioIr, SlotRef, TemplateBinding, TemplateConfigField,
    ir::{BindingFromIr, BindingIr, ComponentExportTargetIr, ComponentIr, ManifestCatalogEntryIr},
};
use axum::{
    Json, Router,
    extract::{Path as AxumPath, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine as _;
use miette::{IntoDiagnostic as _, Result, WrapErr as _};
use reqwest::Client as ReqwestClient;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::{net::TcpListener, signal, sync::Mutex};

use crate::mixed_run::{
    BridgeProxyHandle, BridgeProxyKey, DesiredExportPeer, LaunchedSite, SiteActuatorPlan,
    SiteReceipt, clear_desired_links_for_consumer, clear_desired_links_for_provider,
    host_service_bind_addr_for_consumer, host_service_host_for_consumer,
    launched_site_from_receipt, read_json as read_run_json, resolve_link_external_url_for_output,
    site_actuator_child_root_for_site, site_state_path, stop_bridge_proxies,
    update_desired_links_for_consumer, update_desired_links_for_provider,
};

const CONTROL_STATE_SCHEMA: &str = "amber.framework_component.control_state";
const CONTROL_STATE_VERSION: u32 = 1;
const CONTROL_SERVICE_PLAN_SCHEMA: &str = "amber.framework_component.control_service_plan";
const CONTROL_SERVICE_PLAN_VERSION: u32 = 1;
const CCS_PLAN_SCHEMA: &str = "amber.framework_component.ccs_plan";
const CCS_PLAN_VERSION: u32 = 1;
const CONTROL_SERVICE_PATH: &str = "/v1/control-state";
const FRAMEWORK_ROUTE_ID_HEADER: &str = "x-amber-route-id";
const FRAMEWORK_PEER_ID_HEADER: &str = "x-amber-peer-id";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct FrozenPlacementState {
    pub(crate) offered_sites: BTreeMap<String, SiteDefinition>,
    pub(crate) defaults: PlacementDefaults,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "route_kind", rename_all = "snake_case")]
pub(crate) enum DynamicInputRouteTarget {
    ComponentProvide { provide: String },
    DynamicExport { export_name: String },
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
    pub(crate) live_children: Vec<LiveChildRecord>,
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct FrameworkCcsPlan {
    pub(crate) schema: String,
    pub(crate) version: u32,
    pub(crate) site_id: String,
    pub(crate) listen_addr: SocketAddr,
    pub(crate) control_state_url: String,
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
        placement: FrozenPlacementState {
            offered_sites: run_plan.offered_sites.clone(),
            defaults: run_plan.defaults.clone(),
            placement_components: run_plan.placement_components.clone(),
            assignments: run_plan.assignments.clone(),
        },
        generation: 0,
        next_child_id: 0,
        next_tx_id: 0,
        next_component_id,
        capability_instances: BTreeMap::new(),
        journal: Vec::new(),
        live_children: Vec::new(),
    };
    refresh_capability_instances(&mut state)?;
    Ok(state)
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

fn persist_control_state(path: &Path, state: &mut FrameworkControlState) -> Result<()> {
    refresh_capability_instances(state)?;
    write_control_state(path, state)
}

fn persist_control_state_update<T>(
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

pub(crate) fn write_control_state_service_plan(
    path: &Path,
    listen_addr: SocketAddr,
    state_path: &Path,
    run_root: &Path,
    state_root: &Path,
    mesh_scope: &str,
) -> Result<FrameworkControlStateServicePlan> {
    let plan = FrameworkControlStateServicePlan {
        schema: CONTROL_SERVICE_PLAN_SCHEMA.to_string(),
        version: CONTROL_SERVICE_PLAN_VERSION,
        listen_addr,
        state_path: state_path.display().to_string(),
        run_root: run_root.display().to_string(),
        state_root: state_root.display().to_string(),
        mesh_scope: mesh_scope.to_string(),
    };
    write_json(path, &plan)?;
    Ok(plan)
}

pub(crate) fn write_framework_ccs_plan(
    path: &Path,
    site_id: &str,
    listen_addr: SocketAddr,
    control_state_url: &str,
) -> Result<FrameworkCcsPlan> {
    let plan = FrameworkCcsPlan {
        schema: CCS_PLAN_SCHEMA.to_string(),
        version: CCS_PLAN_VERSION,
        site_id: site_id.to_string(),
        listen_addr,
        control_state_url: control_state_url.to_string(),
    };
    write_json(path, &plan)?;
    Ok(plan)
}

pub(crate) fn authorize_capability_instance<'a>(
    state: &'a FrameworkControlState,
    cap_instance_id: &str,
    peer_id: &str,
) -> std::result::Result<&'a CapabilityInstanceRecord, ProtocolErrorResponse> {
    let record = state
        .capability_instances
        .get(cap_instance_id)
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::Unauthorized,
                "unknown framework capability instance",
            )
        })?;
    if record.recipient_peer_id != peer_id {
        return Err(protocol_error(
            ProtocolErrorCode::Unauthorized,
            "framework capability instance is not bound to the authenticated mesh peer",
        ));
    }
    Ok(record)
}

pub(crate) fn list_templates(
    state: &FrameworkControlState,
    authority_realm_id: usize,
) -> std::result::Result<TemplateListResponse, ProtocolErrorResponse> {
    let scenario = decode_base_scenario(state)?;
    let component = scenario.component(ComponentId(authority_realm_id));
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
    let scenario = decode_base_scenario(state)?;
    let scenario_ir = &state.base_scenario;
    let component = scenario.component(ComponentId(authority_realm_id));
    let template = component
        .child_templates
        .get(template_name)
        .ok_or_else(|| {
            protocol_error(ProtocolErrorCode::UnknownTemplate, "unknown child template")
        })?;
    let manifest = template_manifest_description(&scenario, template)?;
    let bindable_sources = bindable_source_candidates(
        &scenario,
        scenario_ir,
        state,
        ComponentId(authority_realm_id),
    )?;
    let template_config = template_config_fields(&scenario, template)?;
    let template_bindings = template_binding_fields(&scenario, template)?;

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
                            let slot_decl = root_template_slot_decl(&scenario, template, name)?;
                            let candidates = bindable_sources
                                .iter()
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
            visible: visible_exports(template, &scenario),
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
        children: state
            .live_children
            .iter()
            .filter(|child| child.authority_realm_id == authority_realm_id)
            .filter(|child| child_is_visible(child))
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
    for child in state
        .live_children
        .iter()
        .filter(|child| child_is_visible(child))
    {
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
    actual_source: BindingFrom,
    source_child_id: Option<u64>,
    weak: bool,
}

#[derive(Clone)]
struct DynamicChildOutputSource {
    export_name: String,
    provider_component: String,
    protocol: String,
    capability_kind: String,
    capability_profile: Option<String>,
}

async fn prepare_child_record(
    state: &mut FrameworkControlState,
    authority_realm_id: usize,
    request: &CreateChildRequest,
) -> std::result::Result<LiveChildRecord, ProtocolErrorResponse> {
    validate_child_name(&request.name)?;
    let current_live_scenario_ir = live_scenario_ir(state)?;
    let live_scenario = decode_live_scenario(state)?;
    let authority_realm = ComponentId(authority_realm_id);
    let authority_component = live_scenario.component(authority_realm);
    let template = authority_component
        .child_templates
        .get(request.template.as_str())
        .ok_or_else(|| {
            protocol_error(ProtocolErrorCode::UnknownTemplate, "unknown child template")
        })?;
    validate_child_name_available(state, authority_realm_id, &request.name)?;
    validate_template_limits(state, authority_realm_id, &request.name, template)?;
    let bindable_sources = bindable_source_candidates(
        &live_scenario,
        &current_live_scenario_ir,
        state,
        authority_realm,
    )?;
    let selected_manifest_catalog_key = select_manifest_catalog_key(template, request)?;
    let rendered_config = build_child_config(&live_scenario, template, request)?;
    let resolved_bindings =
        resolve_template_bindings(&live_scenario, template, request, &bindable_sources)?;
    let child_id = allocate_child_id(state);
    let (wrapper_manifest, synthetic_sources) = build_wrapper_manifest(
        state,
        &live_scenario,
        template,
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
        assignments: BTreeMap::new(),
        site_plans: Vec::new(),
        overlay_ids: Vec::new(),
        overlays: Vec::new(),
        outputs,
    };

    let mut temporary = state.clone();
    let mut temporary_child = child.clone();
    temporary_child.state = ChildState::Live;
    temporary.live_children.push(temporary_child);
    let planned = build_run_plan(
        &CompiledScenario::from_ir(live_scenario_ir(&temporary)?).map_err(|err| {
            protocol_error(
                ProtocolErrorCode::PlacementUnsatisfied,
                &format!("failed to materialize live scenario for placement: {err}"),
            )
        })?,
        Some(&placement_file_from_state(state)),
    )
    .map_err(|err| {
        protocol_error(
            ProtocolErrorCode::PlacementUnsatisfied,
            &format!("child placement could not be satisfied: {err}"),
        )
    })?;
    child.assignments =
        child_fragment_assignments(&planned, child.fragment.as_ref().expect("fragment set"));
    child.overlays =
        dynamic_overlay_records(&planned, child.fragment.as_ref().expect("fragment set"));
    let routed_inputs = dynamic_input_route_records(
        &planned,
        child.fragment.as_ref().expect("fragment set"),
        &resolved_bindings,
    );
    child.site_plans = dynamic_site_plans(
        &planned,
        child.fragment.as_ref().expect("fragment set"),
        &child.outputs,
        &child.overlays,
        &routed_inputs,
    )?;
    child.overlay_ids = child
        .overlays
        .iter()
        .map(|overlay| overlay.overlay_id.clone())
        .collect();
    Ok(child)
}

fn remove_incident_bindings_from_survivors(state: &mut FrameworkControlState, child_id: u64) {
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
}

#[cfg(test)]
async fn create_child(
    state: &mut FrameworkControlState,
    authority_realm_id: usize,
    request: CreateChildRequest,
    state_path: &Path,
) -> std::result::Result<CreateChildResponse, ProtocolErrorResponse> {
    let child = prepare_child_record(state, authority_realm_id, &request).await?;
    persist_control_state_update(state, state_path, "create_prepared", |state| {
        state.live_children.push(child.clone());
        append_journal_entry(state, &child, ChildState::CreateRequested);
        append_journal_entry(state, &child, ChildState::CreatePrepared);
        Ok(())
    })?;

    persist_control_state_update(state, state_path, "create_committed_hidden", |state| {
        transition_child_state(state, child.child_id, ChildState::CreateCommittedHidden)?;
        append_journal_entry(state, &child, ChildState::CreateCommittedHidden);
        Ok(())
    })?;

    persist_control_state_update(state, state_path, "create_live", |state| {
        transition_child_state(state, child.child_id, ChildState::Live)?;
        append_journal_entry(state, &child, ChildState::Live);
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
async fn destroy_child(
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

    persist_control_state_update(state, state_path, "destroy_requested", |state| {
        append_journal_entry(state, &child, ChildState::DestroyRequested);
        transition_child_state(state, child_id, ChildState::DestroyRequested)?;
        Ok(())
    })?;

    persist_control_state_update(state, state_path, "destroy_retracted", |state| {
        remove_incident_bindings_from_survivors(state, child_id);
        transition_child_state(state, child_id, ChildState::DestroyRetracted)?;
        append_journal_entry(state, &child, ChildState::DestroyRetracted);
        Ok(())
    })?;

    persist_control_state_update(state, state_path, "destroy_committed", |state| {
        append_journal_entry(state, &child, ChildState::DestroyCommitted);
        state
            .live_children
            .retain(|candidate| candidate.child_id != child_id);
        Ok(())
    })?;
    Ok(())
}

fn child_is_visible(child: &LiveChildRecord) -> bool {
    matches!(child.state, ChildState::Live | ChildState::DestroyRequested)
}

fn validate_child_name(name: &str) -> std::result::Result<(), ProtocolErrorResponse> {
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

fn validate_child_name_available(
    state: &FrameworkControlState,
    authority_realm_id: usize,
    child_name: &str,
) -> std::result::Result<(), ProtocolErrorResponse> {
    if state.live_children.iter().any(|child| {
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

fn validate_template_limits(
    state: &FrameworkControlState,
    authority_realm_id: usize,
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
            .filter(|child| child.authority_realm_id == authority_realm_id)
            .filter(|child| child_is_visible(child))
            .count() as u32;
        if live >= limit {
            return Err(protocol_error(
                ProtocolErrorCode::NameConflict,
                &format!("authority realm already has the maximum of {limit} live children"),
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

fn select_manifest_catalog_key(
    template: &ChildTemplate,
    request: &CreateChildRequest,
) -> std::result::Result<String, ProtocolErrorResponse> {
    match (&template.manifest, &template.allowed_manifests) {
        (Some(key), None) => {
            if request.manifest.is_some() {
                return Err(protocol_error(
                    ProtocolErrorCode::ManifestNotAllowed,
                    "exact child templates must not specify `manifest` in CreateChild",
                ));
            }
            Ok(key.clone())
        }
        (None, Some(allowed)) => {
            let selected = request.manifest.as_ref().ok_or_else(|| {
                protocol_error(
                    ProtocolErrorCode::ManifestNotAllowed,
                    "open child templates must specify `manifest.catalog_key` in CreateChild",
                )
            })?;
            if !allowed
                .iter()
                .any(|candidate| candidate == &selected.catalog_key)
            {
                return Err(protocol_error(
                    ProtocolErrorCode::ManifestNotAllowed,
                    &format!(
                        "manifest catalog key `{}` is not allowed for template `{}`",
                        selected.catalog_key, request.template
                    ),
                ));
            }
            Ok(selected.catalog_key.clone())
        }
        _ => unreachable!("validated child template shape"),
    }
}

fn build_child_config(
    scenario: &Scenario,
    template: &ChildTemplate,
    request: &CreateChildRequest,
) -> std::result::Result<Option<serde_json::Value>, ProtocolErrorResponse> {
    let template_config = template_config_fields(scenario, template)?;
    for key in request.config.keys() {
        if !template_config.contains_key(key.as_str()) {
            return Err(protocol_error(
                ProtocolErrorCode::InvalidConfig,
                &format!("unknown child config field `{key}`"),
            ));
        }
    }

    let mut config = serde_json::Map::new();
    for (name, field) in &template_config {
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

fn resolve_template_bindings(
    scenario: &Scenario,
    template: &ChildTemplate,
    request: &CreateChildRequest,
    bindable_sources: &[BindableSourceCandidate],
) -> std::result::Result<Vec<ResolvedTemplateBinding>, ProtocolErrorResponse> {
    let template_bindings = template_binding_fields(scenario, template)?;
    for key in request.bindings.keys() {
        if !template_bindings.contains_key(key.as_str()) {
            return Err(protocol_error(
                ProtocolErrorCode::InvalidBinding,
                &format!("unknown child binding field `{key}`"),
            ));
        }
    }

    template_bindings
        .iter()
        .map(|(slot_name, field)| {
            let slot_decl = root_template_slot_decl(scenario, template, slot_name)?.clone();
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
                    if !source_compatible(slot_decl.decl.clone(), selected.decl.clone()) {
                        return Err(protocol_error(
                            ProtocolErrorCode::BindingTypeMismatch,
                            &format!(
                                "binding `{slot_name}` expects `{}` but `{}` provides `{}`",
                                slot_decl.decl.kind, selected.selector, selected.decl.kind
                            ),
                        ));
                    }
                    Some(selected)
                }
            };

            Ok(candidate.map(|candidate| ResolvedTemplateBinding {
                slot_name: slot_name.clone(),
                slot_decl,
                sources: candidate.sources.clone(),
                source_child_id: candidate.source_child_id,
                dynamic_child_output: candidate.dynamic_child_output.clone(),
            }))
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .map(|bindings| bindings.into_iter().flatten().collect())
}

fn build_wrapper_manifest(
    state: &FrameworkControlState,
    scenario: &Scenario,
    template: &ChildTemplate,
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

    let exports = visible_exports(template, scenario)
        .into_iter()
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

fn raw_binding(
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

fn component_ref_from_url(
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

fn wrapper_manifest_url(authority_realm_id: usize, child_id: u64) -> url::Url {
    url::Url::parse(&format!(
        "amber+framework://rendered-child/{authority_realm_id}/{child_id}"
    ))
    .expect("synthetic wrapper URL should parse")
}

fn allocate_child_id(state: &mut FrameworkControlState) -> u64 {
    state.next_child_id += 1;
    state.next_child_id
}

fn append_journal_entry(
    state: &mut FrameworkControlState,
    child: &LiveChildRecord,
    child_state: ChildState,
) {
    state.next_tx_id += 1;
    state.generation += 1;
    state.journal.push(ControlJournalEntry {
        tx_id: state.next_tx_id,
        child_id: child.child_id,
        authority_realm_id: child.authority_realm_id,
        child_name: child.name.clone(),
        state: child_state,
        generation: state.generation,
    });
}

fn transition_child_state(
    state: &mut FrameworkControlState,
    child_id: u64,
    next_state: ChildState,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let child = state
        .live_children
        .iter_mut()
        .find(|child| child.child_id == child_id)
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &format!("child id {child_id} is missing from authoritative state"),
            )
        })?;
    child.state = next_state;
    Ok(())
}

fn child_fragment_assignments(
    run_plan: &RunPlan,
    fragment: &LiveScenarioFragment,
) -> BTreeMap<String, String> {
    fragment
        .components
        .iter()
        .filter_map(|component| {
            run_plan
                .assignments
                .get(component.moniker.as_str())
                .map(|site_id| (component.moniker.clone(), site_id.clone()))
        })
        .collect()
}

fn dynamic_site_plans(
    desired_run_plan: &RunPlan,
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
    for (site_id, desired_site_plan) in &desired_run_plan.sites {
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
                    (desired_run_plan.assignments.get(*moniker)? == site_id).then_some((
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
        site_plans.push(DynamicSitePlanRecord {
            site_id: site_id.clone(),
            kind: desired_site_plan.site.kind,
            router_identity_id: desired_site_plan.router_identity_id.clone(),
            component_ids,
            assigned_components,
            artifact_files: desired_site_plan.artifact_files.clone(),
            desired_artifact_files: desired_site_plan.artifact_files.clone(),
            proxy_exports,
            routed_inputs: routed_inputs
                .iter()
                .filter(|input| input.component == child_monikers[&fragment.root_component_id])
                .filter(|input| {
                    desired_run_plan
                        .assignments
                        .get(input.component.as_str())
                        .is_some_and(|assigned_site| assigned_site == site_id)
                })
                .cloned()
                .collect(),
        });
    }
    Ok(site_plans)
}

fn dynamic_input_route_records(
    run_plan: &RunPlan,
    fragment: &LiveScenarioFragment,
    resolved_bindings: &[ResolvedTemplateBinding],
) -> Vec<DynamicInputRouteRecord> {
    let Some(root_component) = fragment
        .components
        .iter()
        .find(|component| component.id == fragment.root_component_id)
    else {
        return Vec::new();
    };
    let Some(child_site) = run_plan.assignments.get(root_component.moniker.as_str()) else {
        return Vec::new();
    };
    let fragment_component_ids = fragment
        .components
        .iter()
        .map(|component| component.id)
        .collect::<BTreeSet<_>>();

    resolved_bindings
        .iter()
        .filter_map(|binding| {
            if let Some(dynamic_output) = binding.dynamic_child_output.as_ref() {
                let provider_site = run_plan
                    .assignments
                    .get(dynamic_output.provider_component.as_str())?;
                if provider_site == child_site {
                    return Some(DynamicInputRouteRecord {
                        component: root_component.moniker.clone(),
                        slot: binding.slot_name.clone(),
                        provider_component: dynamic_output.provider_component.clone(),
                        protocol: dynamic_output.protocol.clone(),
                        capability_kind: dynamic_output.capability_kind.clone(),
                        capability_profile: dynamic_output.capability_profile.clone(),
                        target: DynamicInputRouteTarget::DynamicExport {
                            export_name: dynamic_output.export_name.clone(),
                        },
                    });
                }
            }

            let [source] = binding.sources.as_slice() else {
                return None;
            };
            let BindingFrom::Component(provide) = &source.from else {
                return None;
            };
            if fragment_component_ids.contains(&provide.component.0) {
                return None;
            }
            let provider_component = run_plan
                .base_scenario
                .components
                .iter()
                .find(|component| component.id == provide.component.0)
                .map(|component| component.moniker.clone())?;
            let provider_site = run_plan.assignments.get(provider_component.as_str())?;
            (provider_site == child_site).then_some(DynamicInputRouteRecord {
                component: root_component.moniker.clone(),
                slot: binding.slot_name.clone(),
                provider_component,
                protocol: match binding.slot_decl.decl.kind.transport() {
                    CapabilityTransport::Http => "http".to_string(),
                    CapabilityTransport::NonNetwork => return None,
                    _ => return None,
                },
                capability_kind: binding.slot_decl.decl.kind.to_string(),
                capability_profile: binding.slot_decl.decl.profile.clone(),
                target: DynamicInputRouteTarget::ComponentProvide {
                    provide: provide.name.clone(),
                },
            })
        })
        .collect()
}

fn dynamic_proxy_export_record(
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

fn dynamic_overlay_records(
    run_plan: &RunPlan,
    fragment: &LiveScenarioFragment,
) -> Vec<DynamicOverlayRecord> {
    let child_monikers = fragment
        .components
        .iter()
        .map(|component| component.moniker.as_str())
        .collect::<BTreeSet<_>>();
    let mut overlays = Vec::new();
    for link in &run_plan.links {
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

fn create_child_response(child: &LiveChildRecord) -> CreateChildResponse {
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

fn extract_live_child_fragment(
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

    let framework_source = synthetic_sources.iter().find_map(|(_, source)| {
        matches!(source.actual_source, BindingFrom::Framework(_)).then_some(source.clone())
    });
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
                let Some(synthetic) = framework_source.as_ref() else {
                    return Err(protocol_error(
                        ProtocolErrorCode::ControlStateUnavailable,
                        "missing framework synthetic source mapping",
                    ));
                };
                rewritten.from = BindingFromIr::from(&synthetic.actual_source);
                rewritten.weak = synthetic.weak;
                synthetic.source_child_id
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
            BindingFromIr::Framework { .. } | BindingFromIr::External { .. } => None,
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

async fn compile_frozen_manifest(
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

fn joined_moniker(parent: &str, child: &str) -> String {
    if parent == "/" {
        child.to_string()
    } else {
        format!("{parent}{child}")
    }
}

fn child_state_keeps_capability_instances(state: ChildState) -> bool {
    matches!(
        state,
        ChildState::CreatePrepared | ChildState::CreateCommittedHidden | ChildState::Live
    )
}

fn refresh_capability_instances(state: &mut FrameworkControlState) -> Result<()> {
    state.capability_instances = collect_capability_instances(state)?;
    Ok(())
}

fn collect_capability_instances(
    state: &FrameworkControlState,
) -> Result<BTreeMap<String, CapabilityInstanceRecord>> {
    let active_children = state
        .live_children
        .iter()
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

fn collect_capability_instance_from_binding(
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

fn template_mode(template: &ChildTemplate) -> TemplateMode {
    if template.manifest.is_some() {
        TemplateMode::Exact
    } else {
        TemplateMode::Open
    }
}

fn template_manifest_description(
    scenario: &Scenario,
    template: &ChildTemplate,
) -> std::result::Result<TemplateManifestDescription, ProtocolErrorResponse> {
    let mut description = TemplateManifestDescription {
        mode: template_mode(template),
        catalog_key: template.manifest.clone(),
        digest: None,
        allowed_catalog_keys: template.allowed_manifests.clone().unwrap_or_default(),
    };
    if let Some(key) = description.catalog_key.as_ref() {
        description.digest = Some(
            scenario
                .manifest_catalog
                .get(key)
                .ok_or_else(|| {
                    protocol_error(
                        ProtocolErrorCode::ControlStateUnavailable,
                        "frozen manifest catalog entry is missing",
                    )
                })?
                .digest
                .to_string(),
        );
    }
    Ok(description)
}

#[derive(Clone)]
struct ResolvedBindingSource {
    from: BindingFrom,
    weak: bool,
}

#[derive(Clone)]
struct BindableSourceCandidate {
    selector: String,
    handle: Option<String>,
    decl: CapabilityDecl,
    sources: Vec<ResolvedBindingSource>,
    source_child_id: Option<u64>,
    dynamic_child_output: Option<DynamicChildOutputSource>,
}

fn placement_file_from_state(state: &FrameworkControlState) -> PlacementFile {
    let mut components = state.placement.placement_components.clone();
    for child in &state.live_children {
        components.extend(child.assignments.clone());
    }
    PlacementFile {
        schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
        version: amber_compiler::run_plan::PLACEMENT_VERSION,
        sites: state.placement.offered_sites.clone(),
        defaults: state.placement.defaults.clone(),
        components,
    }
}

fn live_scenario_ir(
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

    for child in state
        .live_children
        .iter()
        .filter(|child| child_is_visible(child))
    {
        let Some(fragment) = child.fragment.as_ref() else {
            continue;
        };
        for component in &fragment.components {
            components.insert(component.id, component.clone());
        }
        bindings.extend(
            fragment
                .bindings
                .iter()
                .map(|binding| binding.binding.clone()),
        );
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

fn decode_live_scenario(
    state: &FrameworkControlState,
) -> std::result::Result<Scenario, ProtocolErrorResponse> {
    Scenario::try_from(live_scenario_ir(state)?).map_err(|err| {
        protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &format!("failed to decode authoritative live scenario: {err}"),
        )
    })
}

fn normalize_scenario_ir_order(scenario_ir: &mut ScenarioIr) {
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
    scenario_ir
        .exports
        .sort_by(|left, right| left.name.cmp(&right.name));
}

fn live_child_component_owner(state: &FrameworkControlState, component_id: usize) -> Option<u64> {
    state
        .live_children
        .iter()
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

fn output_sources_from_record(
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

fn bindable_source_candidates(
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
            dynamic_child_output: None,
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
                dynamic_child_output: None,
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
                dynamic_child_output: None,
            }),
    );
    out.extend(static_child_export_candidates(
        scenario,
        scenario_ir,
        state,
        authority_realm,
    )?);

    for child in state
        .live_children
        .iter()
        .filter(|child| child.authority_realm_id == authority_realm.0)
        .filter(|child| child_is_visible(child))
    {
        for (export_name, output) in &child.outputs {
            out.push(BindableSourceCandidate {
                selector: format!("children.{}.exports.{export_name}", child.name),
                handle: output.handle.clone(),
                decl: output.decl.clone(),
                sources: output_sources_from_record(output)?,
                source_child_id: Some(child.child_id),
                dynamic_child_output: dynamic_child_output_source(child, export_name, output),
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
                            dynamic_child_output: None,
                        })
                }),
        );
    }

    Ok(out)
}

fn slot_binding_sources(
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

fn static_child_export_candidates(
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
                dynamic_child_output: None,
            });
        }
    }

    Ok(out)
}

fn component_ir(
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

struct ResolvedComponentExportCandidate {
    decl: CapabilityDecl,
    sources: Vec<ResolvedBindingSource>,
}

fn resolve_component_export_candidate(
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

fn resolve_component_export_candidate_inner(
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

fn resolve_component_export_candidate_target(
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

fn child_alias<'a>(parent_moniker: &str, child_moniker: &'a str) -> Option<&'a str> {
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

fn dynamic_child_output_source(
    child: &LiveChildRecord,
    export_name: &str,
    output: &OutputHandleRecord,
) -> Option<DynamicChildOutputSource> {
    let BindingFromIr::Component {
        component,
        provide: _,
    } = output.sources.first()?.from.clone()
    else {
        return None;
    };
    let provider_component = child
        .fragment
        .as_ref()?
        .components
        .iter()
        .find(|candidate| candidate.id == component)?
        .moniker
        .clone();
    let protocol = match output.decl.kind.transport() {
        CapabilityTransport::Http => "http",
        CapabilityTransport::NonNetwork => return None,
        _ => return None,
    };
    Some(DynamicChildOutputSource {
        export_name: export_name.to_string(),
        provider_component,
        protocol: protocol.to_string(),
        capability_kind: output.decl.kind.to_string(),
        capability_profile: output.decl.profile.clone(),
    })
}

fn find_bindable_source<'a>(
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

fn find_bindable_source_by_handle<'a>(
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

fn runtime_backend_name(backend: &amber_manifest::RuntimeBackend) -> String {
    serde_json::to_value(backend)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "unknown".to_string())
}

fn root_template_manifest<'a>(
    scenario: &'a Scenario,
    template: &'a ChildTemplate,
) -> std::result::Result<&'a Manifest, ProtocolErrorResponse> {
    let key = template
        .manifest
        .as_ref()
        .or_else(|| {
            template
                .allowed_manifests
                .as_ref()
                .and_then(|keys| keys.first())
        })
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                "child template is missing its frozen manifest catalog key",
            )
        })?;
    scenario
        .manifest_catalog
        .get(key)
        .map(|entry| &entry.manifest)
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                "child template root manifest is missing from the frozen manifest catalog entry",
            )
        })
}

fn template_config_fields(
    scenario: &Scenario,
    template: &ChildTemplate,
) -> std::result::Result<BTreeMap<String, TemplateConfigField>, ProtocolErrorResponse> {
    let mut fields = template.config.clone();
    let manifest = root_template_manifest(scenario, template)?;
    let Some(schema) = manifest.config_schema() else {
        return Ok(fields);
    };
    let required = schema
        .0
        .get("required")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .collect::<BTreeSet<_>>();
    for name in schema
        .0
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .into_iter()
        .flat_map(|properties| properties.keys())
    {
        fields
            .entry(name.clone())
            .or_insert(TemplateConfigField::Open {
                required: required.contains(name.as_str()),
            });
    }
    Ok(fields)
}

fn template_binding_fields(
    scenario: &Scenario,
    template: &ChildTemplate,
) -> std::result::Result<BTreeMap<String, TemplateBinding>, ProtocolErrorResponse> {
    let mut fields = template.bindings.clone();
    let manifest = root_template_manifest(scenario, template)?;
    for (name, slot) in manifest.slots() {
        fields
            .entry(name.to_string())
            .or_insert(TemplateBinding::Open {
                optional: slot.optional,
            });
    }
    Ok(fields)
}

fn root_template_slot_decl<'a>(
    scenario: &'a Scenario,
    template: &'a ChildTemplate,
    slot_name: &str,
) -> std::result::Result<&'a amber_manifest::SlotDecl, ProtocolErrorResponse> {
    root_template_manifest(scenario, template)?
        .slots()
        .get(slot_name)
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                "child template root slot is missing from the frozen manifest catalog entry",
            )
        })
}

fn visible_exports(template: &ChildTemplate, scenario: &Scenario) -> Vec<String> {
    if let Some(visible) = template.visible_exports.as_ref() {
        return visible.clone();
    }
    let Some(key) = template.manifest.as_ref().or_else(|| {
        template
            .allowed_manifests
            .as_ref()
            .and_then(|keys| keys.first())
    }) else {
        return Vec::new();
    };
    scenario
        .manifest_catalog
        .get(key)
        .map(|entry| {
            entry
                .manifest
                .exports()
                .keys()
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn source_compatible(target: CapabilityDecl, candidate: CapabilityDecl) -> bool {
    target.kind == candidate.kind && target.profile == candidate.profile
}

fn decode_base_scenario(
    state: &FrameworkControlState,
) -> std::result::Result<Scenario, ProtocolErrorResponse> {
    Scenario::try_from(state.base_scenario.clone()).map_err(|err| {
        protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &format!("failed to decode frozen base scenario: {err}"),
        )
    })
}

fn binding_from_from_ir(
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

fn live_binding_source_record(from: &BindingFrom, weak: bool) -> LiveBindingSourceRecord {
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
struct FrozenCatalogBackend {
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

fn frozen_catalog_schemes<'a>(
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
struct ControlStateApp {
    control_state: Arc<Mutex<FrameworkControlState>>,
    client: ReqwestClient,
    state_path: PathBuf,
    run_root: PathBuf,
    state_root: PathBuf,
    mesh_scope: Arc<str>,
    bridge_proxies: Arc<Mutex<BTreeMap<BridgeProxyKey, BridgeProxyHandle>>>,
}

#[derive(Clone)]
struct CcsApp {
    client: ReqwestClient,
    control_state_url: Arc<str>,
}

#[derive(Clone, Debug, Deserialize)]
struct SiteManagerStateView {
    status: String,
    kind: SiteKind,
    artifact_dir: String,
    supervisor_pid: u32,
    #[serde(default)]
    process_pid: Option<u32>,
    #[serde(default)]
    compose_project: Option<String>,
    #[serde(default)]
    kubernetes_namespace: Option<String>,
    #[serde(default)]
    port_forward_pid: Option<u32>,
    #[serde(default)]
    context: Option<String>,
    #[serde(default)]
    router_control: Option<String>,
    #[serde(default)]
    router_mesh_addr: Option<String>,
    #[serde(default)]
    router_identity_id: Option<String>,
    #[serde(default)]
    router_public_key_b64: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SiteActuatorPrepareRequest {
    pub(crate) site_plan: DynamicSitePlanRecord,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SiteActuatorPublishRequest {
    pub(crate) site_plan: DynamicSitePlanRecord,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct SiteActuatorDestroyRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) desired_site_plan: Option<DynamicSitePlanRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ControlCreateChildRequest {
    authority_realm_id: usize,
    request: CreateChildRequest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ControlDestroyChildRequest {
    authority_realm_id: usize,
}

#[derive(Debug)]
struct ProtocolApiError(ProtocolErrorResponse);

impl ProtocolApiError {
    fn control_state_unavailable(message: impl Into<String>) -> Self {
        Self(ProtocolErrorResponse {
            code: ProtocolErrorCode::ControlStateUnavailable,
            message: message.into(),
            details: None,
        })
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self(ProtocolErrorResponse {
            code: ProtocolErrorCode::Unauthorized,
            message: message.into(),
            details: None,
        })
    }

    fn status_code(&self) -> StatusCode {
        match self.0.code {
            ProtocolErrorCode::Unauthorized => StatusCode::FORBIDDEN,
            ProtocolErrorCode::UnknownTemplate
            | ProtocolErrorCode::UnknownChild
            | ProtocolErrorCode::BindingSourceNotFound => StatusCode::NOT_FOUND,
            ProtocolErrorCode::NameConflict => StatusCode::CONFLICT,
            ProtocolErrorCode::ControlStateUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            ProtocolErrorCode::PrepareFailed | ProtocolErrorCode::PublishFailed => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            ProtocolErrorCode::ManifestNotAllowed
            | ProtocolErrorCode::InvalidConfig
            | ProtocolErrorCode::InvalidBinding
            | ProtocolErrorCode::BindingTypeMismatch
            | ProtocolErrorCode::PlacementUnsatisfied
            | ProtocolErrorCode::SiteNotActive
            | ProtocolErrorCode::ScopeNotAllowed => StatusCode::BAD_REQUEST,
        }
    }
}

impl From<ProtocolErrorResponse> for ProtocolApiError {
    fn from(value: ProtocolErrorResponse) -> Self {
        Self(value)
    }
}

impl IntoResponse for ProtocolApiError {
    fn into_response(self) -> Response {
        (self.status_code(), Json(self.0)).into_response()
    }
}

fn control_state_step_error(step: &str, err: impl std::fmt::Display) -> ProtocolErrorResponse {
    protocol_error(
        ProtocolErrorCode::ControlStateUnavailable,
        &format!("failed to persist {step}: {err}"),
    )
}

fn actuator_protocol_error(
    code: ProtocolErrorCode,
    site_id: &str,
    action: &str,
    detail: impl std::fmt::Display,
) -> ProtocolErrorResponse {
    protocol_error(
        code,
        &format!("failed to {action} on site `{site_id}`: {detail}"),
    )
}

fn site_state_root_for(app: &ControlStateApp, site_id: &str) -> PathBuf {
    Path::new(&app.state_root).join(site_id)
}

fn site_actuator_plan_path_for_site(app: &ControlStateApp, site_id: &str) -> PathBuf {
    site_state_root_for(app, site_id).join("site-actuator-plan.json")
}

fn site_actuator_base_url(plan: &SiteActuatorPlan) -> String {
    format!("http://{}", plan.listen_addr)
}

fn site_receipt_from_manager_state(state: &SiteManagerStateView) -> SiteReceipt {
    SiteReceipt {
        kind: state.kind,
        artifact_dir: state.artifact_dir.clone(),
        supervisor_pid: state.supervisor_pid,
        process_pid: state.process_pid,
        compose_project: state.compose_project.clone(),
        kubernetes_namespace: state.kubernetes_namespace.clone(),
        port_forward_pid: state.port_forward_pid,
        context: state.context.clone(),
        router_control: state.router_control.clone(),
        router_mesh_addr: state.router_mesh_addr.clone(),
        router_identity_id: state.router_identity_id.clone(),
        router_public_key_b64: state.router_public_key_b64.clone(),
    }
}

fn full_site_plan_record(
    site_id: &str,
    site_plan: &amber_compiler::run_plan::RunSitePlan,
) -> DynamicSitePlanRecord {
    DynamicSitePlanRecord {
        site_id: site_id.to_string(),
        kind: site_plan.site.kind,
        router_identity_id: site_plan.router_identity_id.clone(),
        component_ids: site_plan
            .scenario_ir
            .components
            .iter()
            .map(|component| component.id)
            .collect(),
        assigned_components: site_plan.assigned_components.clone(),
        artifact_files: site_plan.artifact_files.clone(),
        desired_artifact_files: site_plan.artifact_files.clone(),
        proxy_exports: BTreeMap::new(),
        routed_inputs: Vec::new(),
    }
}

fn desired_site_plan_map(
    state: &FrameworkControlState,
) -> std::result::Result<BTreeMap<String, DynamicSitePlanRecord>, ProtocolErrorResponse> {
    let planned = build_run_plan(
        &CompiledScenario::from_ir(live_scenario_ir(state)?).map_err(|err| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &format!("failed to materialize live scenario for desired site plans: {err}"),
            )
        })?,
        Some(&placement_file_from_state(state)),
    )
    .map_err(|err| {
        protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &format!("failed to rebuild desired site plans: {err}"),
        )
    })?;
    Ok(planned
        .sites
        .iter()
        .map(|(site_id, site_plan)| (site_id.clone(), full_site_plan_record(site_id, site_plan)))
        .collect())
}

fn load_site_manager_state(
    app: &ControlStateApp,
    site_id: &str,
) -> std::result::Result<SiteManagerStateView, ProtocolErrorResponse> {
    read_run_json(
        &site_state_path(&app.state_root, site_id),
        "site manager state",
    )
    .map_err(|err| {
        protocol_error(
            ProtocolErrorCode::SiteNotActive,
            &format!("site `{site_id}` manager state is unavailable: {err}"),
        )
    })
}

fn load_launched_site(
    app: &ControlStateApp,
    site_id: &str,
) -> std::result::Result<LaunchedSite, ProtocolErrorResponse> {
    let state = load_site_manager_state(app, site_id)?;
    if state.status != "running" {
        return Err(protocol_error(
            ProtocolErrorCode::SiteNotActive,
            &format!("site `{site_id}` is not running"),
        ));
    }
    let receipt = site_receipt_from_manager_state(&state);
    launched_site_from_receipt(&receipt, &app.mesh_scope).map_err(|err| {
        protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &format!("site `{site_id}` routing metadata is invalid: {err}"),
        )
    })
}

fn load_site_actuator_plan(
    app: &ControlStateApp,
    site_id: &str,
) -> std::result::Result<SiteActuatorPlan, ProtocolErrorResponse> {
    let path = site_actuator_plan_path_for_site(app, site_id);
    read_json(&path, "site actuator plan").map_err(|err| {
        protocol_error(
            ProtocolErrorCode::SiteNotActive,
            &format!("site `{site_id}` actuator plan is unavailable: {err}"),
        )
    })
}

async fn call_site_actuator<B: Serialize>(
    app: &ControlStateApp,
    site_id: &str,
    path: &str,
    body: Option<&B>,
    error_code: ProtocolErrorCode,
    action: &str,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let plan = load_site_actuator_plan(app, site_id)?;
    let url = format!("{}{}", site_actuator_base_url(&plan), path);
    let request = app.client.post(url);
    let request = if let Some(body) = body {
        request.json(body)
    } else {
        request
    };
    let response = request
        .send()
        .await
        .map_err(|err| actuator_protocol_error(error_code, site_id, action, err))?;
    if response.status().is_success() {
        return Ok(());
    }
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    Err(actuator_protocol_error(
        error_code,
        site_id,
        action,
        format!("HTTP {status}: {}", body.trim()),
    ))
}

async fn prepare_child_on_site(
    app: &ControlStateApp,
    child_id: u64,
    site_plan: &DynamicSitePlanRecord,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let path = format!("/v1/children/{child_id}/prepare");
    call_site_actuator(
        app,
        &site_plan.site_id,
        &path,
        Some(&SiteActuatorPrepareRequest {
            site_plan: site_plan.clone(),
        }),
        ProtocolErrorCode::PrepareFailed,
        "prepare child",
    )
    .await
}

async fn publish_child_on_site(
    app: &ControlStateApp,
    child_id: u64,
    site_plan: &DynamicSitePlanRecord,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let path = format!("/v1/children/{child_id}/publish");
    call_site_actuator(
        app,
        &site_plan.site_id,
        &path,
        Some(&SiteActuatorPublishRequest {
            site_plan: site_plan.clone(),
        }),
        ProtocolErrorCode::PublishFailed,
        "publish child",
    )
    .await
}

async fn rollback_child_on_site(app: &ControlStateApp, child_id: u64, site_id: &str) -> Result<()> {
    let path = format!("/v1/children/{child_id}/rollback");
    let plan = load_site_actuator_plan(app, site_id)
        .map_err(|err| miette::miette!("failed to load site actuator plan: {}", err.message))?;
    let url = format!("{}{}", site_actuator_base_url(&plan), path);
    let response = app
        .client
        .post(url)
        .send()
        .await
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to rollback child on site `{site_id}`"))?;
    if response.status().is_success() {
        return Ok(());
    }
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    Err(miette::miette!(
        "failed to rollback child on site `{site_id}`: HTTP {status}: {}",
        body.trim()
    ))
}

async fn destroy_child_on_site(
    app: &ControlStateApp,
    child_id: u64,
    site_id: &str,
    desired_site_plan: Option<DynamicSitePlanRecord>,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let path = format!("/v1/children/{child_id}/destroy");
    call_site_actuator(
        app,
        site_id,
        &path,
        Some(&SiteActuatorDestroyRequest { desired_site_plan }),
        ProtocolErrorCode::ControlStateUnavailable,
        "destroy child",
    )
    .await
}

async fn publish_external_slot_overlay(
    app: &ControlStateApp,
    child: &LiveChildRecord,
    link: &RunLink,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let provider = load_launched_site(app, &link.provider_site)?;
    let consumer = load_launched_site(app, &link.consumer_site)?;
    let provider_output_dir =
        provider_output_dir_for_link(app, child, Path::new(&provider.receipt.artifact_dir), link);
    let external_url = {
        let mut bridge_proxies = app.bridge_proxies.lock().await;
        resolve_link_external_url_for_output(
            &provider,
            &provider_output_dir,
            link,
            consumer.receipt.kind,
            &app.run_root,
            &mut bridge_proxies,
        )
        .await
        .map_err(|err| {
            actuator_protocol_error(
                ProtocolErrorCode::PublishFailed,
                &link.consumer_site,
                "compute external slot overlay",
                err,
            )
        })?
    };
    register_external_slot_with_retry(
        &consumer.router_control,
        &link.external_slot_name,
        &external_url,
        Duration::from_secs(30),
    )
    .await
    .map_err(|err| {
        actuator_protocol_error(
            ProtocolErrorCode::PublishFailed,
            &link.consumer_site,
            "publish external slot overlay",
            err,
        )
    })?;
    update_desired_links_for_consumer(
        &site_state_root_for(app, &link.consumer_site),
        &link.external_slot_name,
        &external_url,
    )
    .map_err(|err| {
        actuator_protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &link.consumer_site,
            "persist desired external slot overlay",
            err,
        )
    })
}

async fn publish_export_peer_overlay(
    app: &ControlStateApp,
    child: &LiveChildRecord,
    link: &RunLink,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let provider = load_launched_site(app, &link.provider_site)?;
    let consumer = load_launched_site(app, &link.consumer_site)?;
    let consumer_key =
        base64::engine::general_purpose::STANDARD.encode(consumer.router_identity.public_key);
    let route_id = export_peer_route_id(child, link)?;
    register_export_peer_with_retry(
        &provider.router_control,
        &link.export_name,
        &consumer.router_identity.id,
        &consumer_key,
        &link.protocol.to_string(),
        Some(&route_id),
        Duration::from_secs(30),
    )
    .await
    .map_err(|err| {
        actuator_protocol_error(
            ProtocolErrorCode::PublishFailed,
            &link.provider_site,
            "publish export-peer overlay",
            err,
        )
    })?;
    update_desired_links_for_provider(
        &site_state_root_for(app, &link.provider_site),
        DesiredExportPeer {
            export_name: link.export_name.clone(),
            peer_id: consumer.router_identity.id,
            peer_key_b64: consumer_key,
            protocol: link.protocol.to_string(),
            route_id: Some(route_id),
        },
    )
    .map_err(|err| {
        actuator_protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &link.provider_site,
            "persist desired export-peer overlay",
            err,
        )
    })
}

fn child_link_records(child: &LiveChildRecord) -> Vec<RunLink> {
    let mut links = BTreeMap::new();
    for overlay in &child.overlays {
        let DynamicOverlayAction::ExternalSlot { link } = &overlay.action else {
            continue;
        };
        links.insert(
            (
                link.provider_site.clone(),
                link.consumer_site.clone(),
                link.export_name.clone(),
                link.external_slot_name.clone(),
            ),
            link.clone(),
        );
    }
    links.into_values().collect()
}

fn provider_output_dir_for_link(
    app: &ControlStateApp,
    child: &LiveChildRecord,
    provider_artifact_dir: &Path,
    link: &RunLink,
) -> PathBuf {
    let provider_in_child = child.fragment.as_ref().is_some_and(|fragment| {
        fragment
            .components
            .iter()
            .any(|component| component.moniker == link.provider_component)
    });
    if !provider_in_child {
        return provider_artifact_dir.to_path_buf();
    }
    site_actuator_child_root_for_site(
        &site_state_root_for(app, &link.provider_site),
        child.child_id,
    )
    .join("artifact")
}

fn export_peer_route_id(
    child: &LiveChildRecord,
    link: &RunLink,
) -> std::result::Result<String, ProtocolErrorResponse> {
    let protocol = link_mesh_protocol(link.protocol).map_err(|err| {
        protocol_error(
            ProtocolErrorCode::PublishFailed,
            &format!(
                "provider link `{}` uses an unsupported mesh transport: {err}",
                link.export_name
            ),
        )
    })?;
    let provider_in_child = child.fragment.as_ref().is_some_and(|fragment| {
        fragment
            .components
            .iter()
            .any(|component| component.moniker == link.provider_component)
    });
    Ok(if provider_in_child {
        router_dynamic_export_route_id(&link.provider_component, &link.export_name, protocol)
    } else {
        router_export_route_id(&link.export_name, protocol)
    })
}

fn link_mesh_protocol(protocol: NetworkProtocol) -> Result<MeshProtocol> {
    Ok(match protocol {
        NetworkProtocol::Http | NetworkProtocol::Https => MeshProtocol::Http,
        NetworkProtocol::Tcp => MeshProtocol::Tcp,
        _ => {
            return Err(miette::miette!(
                "mixed-site mesh links do not support protocol `{protocol}`"
            ));
        }
    })
}

async fn publish_link_overlays(
    app: &ControlStateApp,
    child: &LiveChildRecord,
    link: &RunLink,
) -> std::result::Result<(), ProtocolErrorResponse> {
    publish_external_slot_overlay(app, child, link).await?;
    publish_export_peer_overlay(app, child, link).await
}

async fn retract_link_overlays(
    app: &ControlStateApp,
    child: &LiveChildRecord,
    link: &RunLink,
) -> std::result::Result<(), ProtocolErrorResponse> {
    clear_external_slot_overlay(app, link).await?;
    clear_export_peer_overlay(app, child, link).await
}

async fn clear_external_slot_overlay(
    app: &ControlStateApp,
    link: &RunLink,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let consumer = load_launched_site(app, &link.consumer_site)?;
    clear_external_slot_with_retry(
        &consumer.router_control,
        &link.external_slot_name,
        Duration::from_secs(30),
    )
    .await
    .map_err(|err| {
        actuator_protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &link.consumer_site,
            "retract external slot overlay",
            err,
        )
    })?;
    clear_desired_links_for_consumer(
        &site_state_root_for(app, &link.consumer_site),
        &link.external_slot_name,
    )
    .map_err(|err| {
        actuator_protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &link.consumer_site,
            "persist external slot retraction",
            err,
        )
    })
}

async fn clear_export_peer_overlay(
    app: &ControlStateApp,
    child: &LiveChildRecord,
    link: &RunLink,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let provider = load_launched_site(app, &link.provider_site)?;
    let consumer = load_launched_site(app, &link.consumer_site)?;
    let consumer_key =
        base64::engine::general_purpose::STANDARD.encode(consumer.router_identity.public_key);
    let route_id = export_peer_route_id(child, link)?;
    unregister_export_peer_with_retry(
        &provider.router_control,
        &link.export_name,
        &consumer.router_identity.id,
        &consumer_key,
        &link.protocol.to_string(),
        Some(&route_id),
        Duration::from_secs(30),
    )
    .await
    .map_err(|err| {
        actuator_protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &link.provider_site,
            "retract export-peer overlay",
            err,
        )
    })?;
    clear_desired_links_for_provider(
        &site_state_root_for(app, &link.provider_site),
        &DesiredExportPeer {
            export_name: link.export_name.clone(),
            peer_id: consumer.router_identity.id,
            peer_key_b64: consumer_key,
            protocol: link.protocol.to_string(),
            route_id: Some(route_id),
        },
    )
    .map_err(|err| {
        actuator_protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &link.provider_site,
            "persist export-peer retraction",
            err,
        )
    })
}

async fn publish_child_overlays(
    app: &ControlStateApp,
    child: &LiveChildRecord,
) -> std::result::Result<(), ProtocolErrorResponse> {
    for link in child_link_records(child) {
        publish_link_overlays(app, child, &link).await?;
    }
    Ok(())
}

async fn retract_child_overlays(
    app: &ControlStateApp,
    child: &LiveChildRecord,
) -> std::result::Result<(), ProtocolErrorResponse> {
    for link in child_link_records(child) {
        retract_link_overlays(app, child, &link).await?;
    }
    Ok(())
}

fn child_site_publish_order(child: &LiveChildRecord) -> Vec<String> {
    let site_ids = child
        .site_plans
        .iter()
        .map(|site_plan| site_plan.site_id.clone())
        .collect::<BTreeSet<_>>();
    let mut incoming = site_ids
        .iter()
        .map(|site_id| (site_id.clone(), BTreeSet::<String>::new()))
        .collect::<BTreeMap<_, _>>();
    let mut outgoing = site_ids
        .iter()
        .map(|site_id| (site_id.clone(), BTreeSet::<String>::new()))
        .collect::<BTreeMap<_, _>>();
    for link in child_link_records(child) {
        if link.weak || link.provider_site == link.consumer_site {
            continue;
        }
        if !site_ids.contains(&link.provider_site) || !site_ids.contains(&link.consumer_site) {
            continue;
        }
        incoming
            .get_mut(&link.consumer_site)
            .expect("consumer site should be tracked")
            .insert(link.provider_site.clone());
        outgoing
            .get_mut(&link.provider_site)
            .expect("provider site should be tracked")
            .insert(link.consumer_site.clone());
    }

    let mut ready = incoming
        .iter()
        .filter(|(_, deps)| deps.is_empty())
        .map(|(site_id, _)| site_id.clone())
        .collect::<Vec<_>>();
    let mut order = Vec::with_capacity(site_ids.len());
    let mut scheduled = BTreeSet::new();
    while let Some(site_id) = ready.pop() {
        if !scheduled.insert(site_id.clone()) {
            continue;
        }
        order.push(site_id.clone());
        for consumer in outgoing
            .get(&site_id)
            .into_iter()
            .flat_map(|sites| sites.iter())
        {
            let deps = incoming
                .get_mut(consumer)
                .expect("consumer dependencies should be tracked");
            deps.remove(&site_id);
            if deps.is_empty() {
                ready.push(consumer.clone());
            }
        }
        ready.sort_by(|left, right| right.cmp(left));
    }

    for site_id in site_ids {
        if scheduled.insert(site_id.clone()) {
            order.push(site_id);
        }
    }
    order
}

fn cloned_child_record(
    state: &FrameworkControlState,
    child_id: u64,
) -> std::result::Result<LiveChildRecord, ProtocolErrorResponse> {
    state
        .live_children
        .iter()
        .find(|child| child.child_id == child_id)
        .cloned()
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &format!("child id {child_id} is missing from authoritative state"),
            )
        })
}

async fn rollback_prepared_sites(
    app: &ControlStateApp,
    child_id: u64,
    prepared_sites: &[String],
) -> Result<()> {
    for site_id in prepared_sites {
        rollback_child_on_site(app, child_id, site_id).await?;
    }
    Ok(())
}

async fn continue_create_committed_hidden(
    app: &ControlStateApp,
    child_id: u64,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let child = {
        let state = app.control_state.lock().await;
        let child = cloned_child_record(&state, child_id)?;
        if child.state != ChildState::CreateCommittedHidden && child.state != ChildState::Live {
            return Ok(());
        }
        child
    };

    let site_plans = child
        .site_plans
        .iter()
        .map(|site_plan| (site_plan.site_id.clone(), site_plan))
        .collect::<BTreeMap<_, _>>();
    for site_id in child_site_publish_order(&child) {
        let site_plan = site_plans.get(&site_id).expect("site plan should exist");
        publish_child_on_site(app, child.child_id, site_plan).await?;
    }
    publish_child_overlays(app, &child).await?;

    let mut state = app.control_state.lock().await;
    let child = cloned_child_record(&state, child_id)?;
    if child.state == ChildState::Live {
        return Ok(());
    }
    if child.state != ChildState::CreateCommittedHidden {
        return Ok(());
    }
    persist_control_state_update(&mut state, &app.state_path, "create_live", |state| {
        transition_child_state(state, child_id, ChildState::Live)?;
        append_journal_entry(state, &child, ChildState::Live);
        Ok(())
    })
}

async fn continue_destroy_retracted(
    app: &ControlStateApp,
    child_id: u64,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let child = {
        let state = app.control_state.lock().await;
        let child = cloned_child_record(&state, child_id)?;
        if child.state != ChildState::DestroyRetracted {
            return Ok(());
        }
        child
    };
    let desired_site_plans = {
        let state = app.control_state.lock().await;
        desired_site_plan_map(&state)?
    };
    for site_plan in &child.site_plans {
        destroy_child_on_site(
            app,
            child.child_id,
            &site_plan.site_id,
            desired_site_plans.get(&site_plan.site_id).cloned(),
        )
        .await?;
    }

    let mut state = app.control_state.lock().await;
    let child = cloned_child_record(&state, child_id)?;
    if child.state != ChildState::DestroyRetracted {
        return Ok(());
    }
    persist_control_state_update(&mut state, &app.state_path, "destroy_committed", |state| {
        append_journal_entry(state, &child, ChildState::DestroyCommitted);
        state
            .live_children
            .retain(|candidate| candidate.child_id != child_id);
        Ok(())
    })
}

async fn continue_destroy_requested(
    app: &ControlStateApp,
    child_id: u64,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let child = {
        let state = app.control_state.lock().await;
        let child = cloned_child_record(&state, child_id)?;
        if child.state != ChildState::DestroyRequested {
            return Ok(());
        }
        child
    };
    retract_child_overlays(app, &child).await?;

    {
        let mut state = app.control_state.lock().await;
        let child = cloned_child_record(&state, child_id)?;
        if child.state != ChildState::DestroyRequested {
            return Ok(());
        }
        persist_control_state_update(&mut state, &app.state_path, "destroy_retracted", |state| {
            remove_incident_bindings_from_survivors(state, child_id);
            transition_child_state(state, child_id, ChildState::DestroyRetracted)?;
            append_journal_entry(state, &child, ChildState::DestroyRetracted);
            Ok(())
        })?;
    }

    continue_destroy_retracted(app, child_id).await
}

async fn execute_create_child(
    app: &ControlStateApp,
    authority_realm_id: usize,
    request: CreateChildRequest,
) -> std::result::Result<CreateChildResponse, ProtocolApiError> {
    let child = {
        let mut state = app.control_state.lock().await;
        let child = prepare_child_record(&mut state, authority_realm_id, &request).await?;
        persist_control_state_update(&mut state, &app.state_path, "create_prepared", |state| {
            state.live_children.push(child.clone());
            append_journal_entry(state, &child, ChildState::CreateRequested);
            append_journal_entry(state, &child, ChildState::CreatePrepared);
            Ok(())
        })?;
        child
    };

    let mut prepared_sites = Vec::new();
    for site_plan in &child.site_plans {
        if let Err(err) = prepare_child_on_site(app, child.child_id, site_plan).await {
            let rollback_err = rollback_prepared_sites(app, child.child_id, &prepared_sites).await;
            let mut state = app.control_state.lock().await;
            if state
                .live_children
                .iter()
                .any(|candidate| candidate.child_id == child.child_id)
            {
                persist_control_state_update(
                    &mut state,
                    &app.state_path,
                    "create_aborted",
                    |state| {
                        append_journal_entry(state, &child, ChildState::CreateAborted);
                        state
                            .live_children
                            .retain(|candidate| candidate.child_id != child.child_id);
                        Ok(())
                    },
                )?;
            }
            let err = if let Err(rollback_err) = rollback_err {
                protocol_error(
                    ProtocolErrorCode::PrepareFailed,
                    &format!("{}; rollback failed: {rollback_err}", err.message),
                )
            } else {
                err
            };
            return Err(err.into());
        }
        prepared_sites.push(site_plan.site_id.clone());
    }

    {
        let mut state = app.control_state.lock().await;
        let child = cloned_child_record(&state, child.child_id)?;
        if child.state != ChildState::CreatePrepared {
            return Err(protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                "prepared child changed state before commit",
            )
            .into());
        }
        persist_control_state_update(
            &mut state,
            &app.state_path,
            "create_committed_hidden",
            |state| {
                transition_child_state(state, child.child_id, ChildState::CreateCommittedHidden)?;
                append_journal_entry(state, &child, ChildState::CreateCommittedHidden);
                Ok(())
            },
        )?;
    }

    continue_create_committed_hidden(app, child.child_id).await?;

    let state = app.control_state.lock().await;
    let live_child = cloned_child_record(&state, child.child_id)?;
    if live_child.state != ChildState::Live {
        return Err(protocol_error(
            ProtocolErrorCode::PublishFailed,
            "child did not become live after publication",
        )
        .into());
    }
    Ok(create_child_response(&live_child))
}

async fn execute_destroy_child(
    app: &ControlStateApp,
    authority_realm_id: usize,
    child_name: &str,
) -> std::result::Result<(), ProtocolApiError> {
    let next = {
        let mut state = app.control_state.lock().await;
        let Some(child) = state
            .live_children
            .iter()
            .find(|child| {
                child.authority_realm_id == authority_realm_id && child.name == child_name
            })
            .cloned()
        else {
            return Ok(());
        };
        match child.state {
            ChildState::Live => {
                persist_control_state_update(
                    &mut state,
                    &app.state_path,
                    "destroy_requested",
                    |state| {
                        append_journal_entry(state, &child, ChildState::DestroyRequested);
                        transition_child_state(
                            state,
                            child.child_id,
                            ChildState::DestroyRequested,
                        )?;
                        Ok(())
                    },
                )?;
                (child.child_id, ChildState::DestroyRequested)
            }
            ChildState::DestroyRequested => (child.child_id, ChildState::DestroyRequested),
            ChildState::DestroyRetracted => (child.child_id, ChildState::DestroyRetracted),
            ChildState::DestroyCommitted | ChildState::CreateAborted => return Ok(()),
            _ => {
                return Err(protocol_error(
                    ProtocolErrorCode::NameConflict,
                    &format!("child `{child_name}` is not in a destroyable state"),
                )
                .into());
            }
        }
    };
    match next.1 {
        ChildState::DestroyRequested => continue_destroy_requested(app, next.0).await?,
        ChildState::DestroyRetracted => continue_destroy_retracted(app, next.0).await?,
        _ => {}
    }
    Ok(())
}

async fn recover_control_state(app: &ControlStateApp) -> Result<()> {
    let children = {
        let state = app.control_state.lock().await;
        state.live_children.clone()
    };
    for child in children {
        match child.state {
            ChildState::CreateRequested => {
                let mut state = app.control_state.lock().await;
                if state
                    .live_children
                    .iter()
                    .any(|candidate| candidate.child_id == child.child_id)
                {
                    persist_control_state_update(
                        &mut state,
                        &app.state_path,
                        "create_aborted",
                        |state| {
                            append_journal_entry(state, &child, ChildState::CreateAborted);
                            state
                                .live_children
                                .retain(|candidate| candidate.child_id != child.child_id);
                            Ok(())
                        },
                    )
                    .map_err(|err| miette::miette!(err.message))?;
                }
            }
            ChildState::CreatePrepared => {
                let prepared_sites = child
                    .site_plans
                    .iter()
                    .map(|site_plan| site_plan.site_id.clone())
                    .collect::<Vec<_>>();
                let _ = rollback_prepared_sites(app, child.child_id, &prepared_sites).await;
                let mut state = app.control_state.lock().await;
                if state
                    .live_children
                    .iter()
                    .any(|candidate| candidate.child_id == child.child_id)
                {
                    persist_control_state_update(
                        &mut state,
                        &app.state_path,
                        "create_aborted",
                        |state| {
                            append_journal_entry(state, &child, ChildState::CreateAborted);
                            state
                                .live_children
                                .retain(|candidate| candidate.child_id != child.child_id);
                            Ok(())
                        },
                    )
                    .map_err(|err| miette::miette!(err.message))?;
                }
            }
            ChildState::CreateCommittedHidden => {
                continue_create_committed_hidden(app, child.child_id)
                    .await
                    .map_err(|err| miette::miette!(err.message))?;
            }
            ChildState::Live => {
                continue_create_committed_hidden(app, child.child_id)
                    .await
                    .map_err(|err| miette::miette!(err.message))?;
            }
            ChildState::DestroyRequested => {
                continue_destroy_requested(app, child.child_id)
                    .await
                    .map_err(|err| miette::miette!(err.message))?;
            }
            ChildState::DestroyRetracted => {
                continue_destroy_retracted(app, child.child_id)
                    .await
                    .map_err(|err| miette::miette!(err.message))?;
            }
            ChildState::CreateAborted | ChildState::DestroyCommitted => {}
        }
    }
    Ok(())
}

pub(crate) async fn run_framework_control_state(plan_path: PathBuf) -> Result<()> {
    let plan: FrameworkControlStateServicePlan =
        read_json(plan_path.as_path(), "framework control-state plan")?;
    let mut control_state: FrameworkControlState =
        read_json(Path::new(&plan.state_path), "framework control-state file")?;
    persist_control_state(Path::new(&plan.state_path), &mut control_state)?;
    let app_state = ControlStateApp {
        control_state: Arc::new(Mutex::new(control_state)),
        client: ReqwestClient::new(),
        state_path: PathBuf::from(&plan.state_path),
        run_root: PathBuf::from(&plan.run_root),
        state_root: PathBuf::from(&plan.state_root),
        mesh_scope: Arc::<str>::from(plan.mesh_scope.clone()),
        bridge_proxies: Arc::new(Mutex::new(BTreeMap::new())),
    };
    recover_control_state(&app_state).await?;
    let app = Router::new()
        .route("/", get(healthz))
        .route("/healthz", get(healthz))
        .route(CONTROL_SERVICE_PATH, get(get_control_state))
        .route("/v1/control-state/children", post(control_create_child))
        .route(
            "/v1/control-state/children/{child}/destroy",
            post(control_destroy_child),
        )
        .with_state(app_state.clone());
    let listener = TcpListener::bind(plan.listen_addr)
        .await
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to bind framework control-state service on {}",
                plan.listen_addr
            )
        })?;
    let serve_result = axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .into_diagnostic();
    let cleanup_result = cleanup_dynamic_bridge_proxies(&app_state).await;
    match (serve_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(err), Ok(())) => Err(err).wrap_err("framework control-state service failed"),
        (Ok(()), Err(err)) => {
            Err(err).wrap_err("framework control-state service failed to stop bridge proxies")
        }
        (Err(serve_err), Err(cleanup_err)) => Err(miette::miette!(
            "framework control-state service failed: {serve_err}\nbridge proxy cleanup failed: \
             {cleanup_err}"
        )),
    }
}

pub(crate) async fn run_framework_ccs(plan_path: PathBuf) -> Result<()> {
    let plan: FrameworkCcsPlan = read_json(plan_path.as_path(), "framework CCS plan")?;
    let app = Router::new()
        .route("/", get(healthz))
        .route("/healthz", get(healthz))
        .route("/v1/templates", get(ccs_list_templates))
        .route("/v1/templates/{template}", get(ccs_describe_template))
        .route(
            "/v1/children",
            get(ccs_list_children).post(ccs_create_child),
        )
        .route(
            "/v1/children/{child}",
            get(ccs_describe_child).delete(ccs_destroy_child),
        )
        .route("/v1/snapshot", post(ccs_snapshot))
        .with_state(CcsApp {
            client: ReqwestClient::new(),
            control_state_url: Arc::<str>::from(plan.control_state_url),
        });
    let listener = TcpListener::bind(plan.listen_addr)
        .await
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to bind framework CCS on {}", plan.listen_addr))?;
    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .into_diagnostic()
        .wrap_err("framework CCS failed")
}

async fn healthz() -> Json<serde_json::Value> {
    Json(json!({ "ok": true }))
}

async fn cleanup_dynamic_bridge_proxies(app: &ControlStateApp) -> Result<()> {
    let mut bridge_proxies = {
        let mut guard = app.bridge_proxies.lock().await;
        std::mem::take(&mut *guard)
    };
    stop_bridge_proxies(&mut bridge_proxies).await
}

async fn get_control_state(State(app): State<ControlStateApp>) -> Json<FrameworkControlState> {
    Json(app.control_state.lock().await.clone())
}

async fn control_create_child(
    State(app): State<ControlStateApp>,
    Json(request): Json<ControlCreateChildRequest>,
) -> std::result::Result<Json<CreateChildResponse>, ProtocolApiError> {
    Ok(Json(
        execute_create_child(&app, request.authority_realm_id, request.request).await?,
    ))
}

async fn control_destroy_child(
    State(app): State<ControlStateApp>,
    AxumPath(child): AxumPath<String>,
    Json(request): Json<ControlDestroyChildRequest>,
) -> std::result::Result<StatusCode, ProtocolApiError> {
    execute_destroy_child(&app, request.authority_realm_id, &child).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn ccs_list_templates(
    State(app): State<CcsApp>,
    headers: HeaderMap,
) -> std::result::Result<Json<TemplateListResponse>, ProtocolApiError> {
    let (_, record, state) = authorize_request(&app, &headers).await?;
    Ok(Json(list_templates(&state, record.authority_realm_id)?))
}

async fn ccs_describe_template(
    State(app): State<CcsApp>,
    headers: HeaderMap,
    AxumPath(template): AxumPath<String>,
) -> std::result::Result<Json<TemplateDescribeResponse>, ProtocolApiError> {
    let (_, record, state) = authorize_request(&app, &headers).await?;
    Ok(Json(describe_template(
        &state,
        record.authority_realm_id,
        &template,
    )?))
}

async fn ccs_list_children(
    State(app): State<CcsApp>,
    headers: HeaderMap,
) -> std::result::Result<Json<ChildListResponse>, ProtocolApiError> {
    let (_, record, state) = authorize_request(&app, &headers).await?;
    Ok(Json(list_children(&state, record.authority_realm_id)))
}

async fn ccs_create_child(
    State(app): State<CcsApp>,
    headers: HeaderMap,
    Json(request): Json<CreateChildRequest>,
) -> std::result::Result<Json<CreateChildResponse>, ProtocolApiError> {
    let (_, record, _) = authorize_request(&app, &headers).await?;
    Ok(Json(
        forward_create_child(&app, record.authority_realm_id, request).await?,
    ))
}

async fn ccs_describe_child(
    State(app): State<CcsApp>,
    headers: HeaderMap,
    AxumPath(child): AxumPath<String>,
) -> std::result::Result<Json<ChildDescribeResponse>, ProtocolApiError> {
    let (_, record, state) = authorize_request(&app, &headers).await?;
    Ok(Json(describe_child(
        &state,
        record.authority_realm_id,
        &child,
    )?))
}

async fn ccs_snapshot(
    State(app): State<CcsApp>,
    headers: HeaderMap,
) -> std::result::Result<Json<SnapshotResponse>, ProtocolApiError> {
    let (_, record, state) = authorize_request(&app, &headers).await?;
    Ok(Json(snapshot(&state, record.authority_realm_id)?))
}

async fn ccs_destroy_child(
    State(app): State<CcsApp>,
    headers: HeaderMap,
    AxumPath(child): AxumPath<String>,
) -> std::result::Result<StatusCode, ProtocolApiError> {
    let (_, record, _) = authorize_request(&app, &headers).await?;
    forward_destroy_child(&app, record.authority_realm_id, &child).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn authorize_request(
    app: &CcsApp,
    headers: &HeaderMap,
) -> std::result::Result<(String, CapabilityInstanceRecord, FrameworkControlState), ProtocolApiError>
{
    let route_id = required_header(headers, FRAMEWORK_ROUTE_ID_HEADER)?;
    let peer_id = required_header(headers, FRAMEWORK_PEER_ID_HEADER)?;
    let state = fetch_control_state(app).await?;
    let record = authorize_capability_instance(&state, &route_id, &peer_id)
        .map_err(ProtocolApiError::from)?
        .clone();
    Ok((peer_id, record, state))
}

fn required_header(
    headers: &HeaderMap,
    name: &str,
) -> std::result::Result<String, ProtocolApiError> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            ProtocolApiError::unauthorized(format!(
                "missing authenticated framework request header `{name}`"
            ))
        })
}

async fn fetch_control_state(
    app: &CcsApp,
) -> std::result::Result<FrameworkControlState, ProtocolApiError> {
    let url = format!(
        "{}{}",
        app.control_state_url.trim_end_matches('/'),
        CONTROL_SERVICE_PATH
    );
    let response = app.client.get(&url).send().await.map_err(|err| {
        ProtocolApiError::control_state_unavailable(format!(
            "failed to reach authoritative control-state service: {err}"
        ))
    })?;
    if !response.status().is_success() {
        return Err(ProtocolApiError::control_state_unavailable(format!(
            "authoritative control-state service returned {}",
            response.status()
        )));
    }
    response.json().await.map_err(|err| {
        ProtocolApiError::control_state_unavailable(format!(
            "authoritative control-state service returned invalid JSON: {err}"
        ))
    })
}

async fn forward_create_child(
    app: &CcsApp,
    authority_realm_id: usize,
    request: CreateChildRequest,
) -> std::result::Result<CreateChildResponse, ProtocolApiError> {
    let url = format!(
        "{}/v1/control-state/children",
        app.control_state_url.trim_end_matches('/')
    );
    let response = app
        .client
        .post(&url)
        .json(&ControlCreateChildRequest {
            authority_realm_id,
            request,
        })
        .send()
        .await
        .map_err(|err| {
            ProtocolApiError::control_state_unavailable(format!(
                "failed to reach authoritative control-state service: {err}"
            ))
        })?;
    parse_control_service_json(response).await
}

async fn forward_destroy_child(
    app: &CcsApp,
    authority_realm_id: usize,
    child: &str,
) -> std::result::Result<(), ProtocolApiError> {
    let url = format!(
        "{}/v1/control-state/children/{child}/destroy",
        app.control_state_url.trim_end_matches('/')
    );
    let response = app
        .client
        .post(&url)
        .json(&ControlDestroyChildRequest { authority_realm_id })
        .send()
        .await
        .map_err(|err| {
            ProtocolApiError::control_state_unavailable(format!(
                "failed to reach authoritative control-state service: {err}"
            ))
        })?;
    parse_control_service_empty(response).await
}

async fn parse_control_service_json<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
) -> std::result::Result<T, ProtocolApiError> {
    if response.status().is_success() {
        return response.json().await.map_err(|err| {
            ProtocolApiError::control_state_unavailable(format!(
                "authoritative control-state service returned invalid JSON: {err}"
            ))
        });
    }
    let status = response.status();
    let body = response.bytes().await.map_err(|err| {
        ProtocolApiError::control_state_unavailable(format!(
            "failed to read authoritative control-state error response: {err}"
        ))
    })?;
    if let Ok(protocol_error) = serde_json::from_slice::<ProtocolErrorResponse>(&body) {
        return Err(protocol_error.into());
    }
    Err(ProtocolApiError::control_state_unavailable(format!(
        "authoritative control-state service returned {status}"
    )))
}

async fn parse_control_service_empty(
    response: reqwest::Response,
) -> std::result::Result<(), ProtocolApiError> {
    if response.status().is_success() {
        return Ok(());
    }
    let status = response.status();
    let body = response.bytes().await.map_err(|err| {
        ProtocolApiError::control_state_unavailable(format!(
            "failed to read authoritative control-state error response: {err}"
        ))
    })?;
    if let Ok(protocol_error) = serde_json::from_slice::<ProtocolErrorResponse>(&body) {
        return Err(protocol_error.into());
    }
    Err(ProtocolApiError::control_state_unavailable(format!(
        "authoritative control-state service returned {status}"
    )))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("framework service should install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};

        signal(SignalKind::terminate())
            .expect("framework service should install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(unix)]
    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }

    #[cfg(not(unix))]
    ctrl_c.await;
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to create {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|err| miette::miette!("failed to serialize {}: {err}", path.display()))?;
    write_bytes_atomic(path, &bytes)
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("tmp");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp_path = path.with_file_name(format!(".{file_name}.tmp-{}-{nonce}", std::process::id()));

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create {}", tmp_path.display()))?;
    if let Err(err) = file.write_all(bytes) {
        let _ = fs::remove_file(&tmp_path);
        return Err(miette::miette!(
            "failed to write {}: {err}",
            tmp_path.display()
        ));
    }
    if let Err(err) = file.sync_all() {
        let _ = fs::remove_file(&tmp_path);
        return Err(miette::miette!(
            "failed to sync {}: {err}",
            tmp_path.display()
        ));
    }
    drop(file);

    fs::rename(&tmp_path, path)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to replace {} with {}",
                path.display(),
                tmp_path.display()
            )
        })?;
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path, label: &str) -> Result<T> {
    let bytes = fs::read(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {label} {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|err| miette::miette!("invalid {label} {}: {err}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;
    use url::Url;

    use super::*;

    fn write_file(path: &Path, contents: &str) {
        fs::write(path, contents).expect("test fixture should write");
    }

    fn file_url(path: &Path) -> String {
        Url::from_file_path(path)
            .expect("test path should convert to file URL")
            .to_string()
    }

    async fn compile_control_state_with_placement(
        root_path: &Path,
        placement: Option<&PlacementFile>,
    ) -> FrameworkControlState {
        let compiler = Compiler::new(Resolver::new(), DigestStore::default());
        let output = compiler
            .compile(
                ManifestRef::from_url(
                    Url::from_file_path(root_path).expect("root path should convert to URL"),
                ),
                CompileOptions::default(),
            )
            .await
            .expect("fixture should compile");
        let compiled = CompiledScenario::from_compile_output(&output)
            .expect("fixture should materialize compiled scenario");
        let run_plan =
            build_run_plan(&compiled, placement).expect("fixture should produce run plan");
        build_control_state("test-run", &run_plan).expect("fixture should build control state")
    }

    async fn compile_control_state(root_path: &Path) -> FrameworkControlState {
        compile_control_state_with_placement(root_path, None).await
    }

    async fn compile_control_state_from_ir(
        scenario_ir: ScenarioIr,
        placement: Option<&PlacementFile>,
    ) -> FrameworkControlState {
        let compiled = CompiledScenario::from_ir(scenario_ir).expect("fixture should load from ir");
        let run_plan =
            build_run_plan(&compiled, placement).expect("fixture should produce replay run plan");
        build_control_state("test-run", &run_plan).expect("fixture should build replay state")
    }

    #[derive(Deserialize)]
    struct SnapshotPlacementFixture {
        offered_sites: BTreeMap<String, SiteDefinition>,
        defaults: PlacementDefaults,
        #[serde(default)]
        assignments: BTreeMap<String, String>,
    }

    fn placement_from_snapshot(snapshot: &SnapshotResponse) -> PlacementFile {
        let placement: SnapshotPlacementFixture =
            serde_json::from_value(snapshot.placement.clone()).expect("snapshot placement");
        PlacementFile {
            schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
            version: amber_compiler::run_plan::PLACEMENT_VERSION,
            sites: placement.offered_sites,
            defaults: placement.defaults,
            components: placement.assignments,
        }
    }

    async fn compile_control_state_from_snapshot(
        snapshot: &SnapshotResponse,
    ) -> FrameworkControlState {
        let scenario_ir: ScenarioIr =
            serde_json::from_value(snapshot.scenario.clone()).expect("snapshot scenario");
        let placement = placement_from_snapshot(snapshot);
        compile_control_state_from_ir(scenario_ir, Some(&placement)).await
    }

    #[test]
    fn framework_ccs_addressing_matches_site_runtime_topology() {
        assert_eq!(
            ccs_listen_addr_for_site(SiteKind::Direct, 41000),
            SocketAddr::from(([127, 0, 0, 1], 41000))
        );
        assert_eq!(
            ccs_url_for_site(SiteKind::Direct, 41000),
            "http://127.0.0.1:41000"
        );
        assert_eq!(
            ccs_listen_addr_for_site(SiteKind::Vm, 42000),
            SocketAddr::from(([127, 0, 0, 1], 42000))
        );
        assert_eq!(
            ccs_url_for_site(SiteKind::Vm, 42000),
            "http://127.0.0.1:42000"
        );
        assert_eq!(
            ccs_listen_addr_for_site(SiteKind::Compose, 43000),
            SocketAddr::from(([0, 0, 0, 0], 43000))
        );
        assert_eq!(
            ccs_url_for_site(SiteKind::Compose, 43000),
            "http://host.docker.internal:43000"
        );
        assert_eq!(
            ccs_listen_addr_for_site(SiteKind::Kubernetes, 44000),
            SocketAddr::from(([0, 0, 0, 0], 44000))
        );
        assert_eq!(
            ccs_url_for_site(SiteKind::Kubernetes, 44000),
            format!(
                "http://{}:44000",
                host_service_host_for_consumer(SiteKind::Kubernetes)
            )
        );
    }

    async fn compile_empty_control_state() -> (TempDir, FrameworkControlState, PathBuf) {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        write_file(
            &root_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: { path: "/bin/echo", args: ["root"] },
            }
            "#,
        );
        let state = compile_control_state(&root_path).await;
        let state_path = dir.path().join("control-state.json");
        write_control_state(&state_path, &state).expect("state should write");
        (dir, state, state_path)
    }

    async fn compile_exact_template_control_state() -> (TempDir, FrameworkControlState, PathBuf) {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let child_path = dir.path().join("child.json5");
        write_file(
            &child_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["child"],
                network: { endpoints: [{ name: "out", port: 8080, protocol: "http" }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
        );
        write_file(
            &root_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  program: {{ path: "/bin/echo", args: ["root"] }},
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{ manifest: "{child}" }}
                  }},
                }}
                "#,
                child = file_url(&child_path),
            ),
        );
        let state = compile_control_state(&root_path).await;
        let state_path = dir.path().join("control-state.json");
        write_control_state(&state_path, &state).expect("state should write");
        (dir, state, state_path)
    }

    fn empty_live_child(
        authority_realm_id: usize,
        name: &str,
        child_id: u64,
        state: ChildState,
    ) -> LiveChildRecord {
        LiveChildRecord {
            child_id,
            authority_realm_id,
            name: name.to_string(),
            state,
            template_name: Some("worker".to_string()),
            selected_manifest_catalog_key: None,
            fragment: None,
            assignments: BTreeMap::new(),
            site_plans: Vec::new(),
            overlay_ids: Vec::new(),
            overlays: Vec::new(),
            outputs: BTreeMap::new(),
        }
    }

    fn test_control_state_app(
        dir: &TempDir,
        state: FrameworkControlState,
        state_path: PathBuf,
    ) -> ControlStateApp {
        let run_root = dir.path().join("run");
        let state_root = dir.path().join("state");
        fs::create_dir_all(&run_root).expect("run root should exist");
        fs::create_dir_all(&state_root).expect("state root should exist");
        ControlStateApp {
            control_state: Arc::new(Mutex::new(state)),
            client: ReqwestClient::new(),
            state_path,
            run_root,
            state_root,
            mesh_scope: Arc::<str>::from("test-mesh"),
            bridge_proxies: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    async fn install_success_site_actuator(
        app: &ControlStateApp,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        let offered_sites = {
            let state = app.control_state.lock().await;
            state
                .placement
                .offered_sites
                .iter()
                .map(|(site_id, site)| (site_id.clone(), site.kind))
                .collect::<Vec<_>>()
        };
        let mut handles = Vec::with_capacity(offered_sites.len());
        for (site_id, site_kind) in offered_sites {
            let site_state_root = Path::new(&app.state_root).join(&site_id);
            fs::create_dir_all(&site_state_root).expect("site state root should exist");
            let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .expect("actuator listener");
            let listen_addr = listener.local_addr().expect("actuator addr");
            write_json(
                &site_state_root.join("site-actuator-plan.json"),
                &SiteActuatorPlan {
                    schema: "amber.run.site_actuator_plan".to_string(),
                    version: 1,
                    run_id: "test-run".to_string(),
                    mesh_scope: "test-mesh".to_string(),
                    run_root: app.run_root.display().to_string(),
                    site_id: site_id.clone(),
                    kind: site_kind,
                    router_identity_id: format!("/site/{site_id}/router"),
                    artifact_dir: site_state_root.join("artifact").display().to_string(),
                    site_state_root: site_state_root.display().to_string(),
                    listen_addr,
                    storage_root: None,
                    runtime_root: None,
                    router_mesh_port: None,
                    compose_project: None,
                    kubernetes_namespace: None,
                    context: None,
                    observability_endpoint: None,
                    launch_env: BTreeMap::new(),
                },
            )
            .expect("site actuator plan should write");
            let app = Router::new()
                .route(
                    "/v1/children/{child_id}/prepare",
                    post(|| async { StatusCode::NO_CONTENT }),
                )
                .route(
                    "/v1/children/{child_id}/publish",
                    post(|| async { StatusCode::NO_CONTENT }),
                )
                .route(
                    "/v1/children/{child_id}/destroy",
                    post(|| async { StatusCode::NO_CONTENT }),
                );
            handles.push(tokio::spawn(async move {
                axum::serve(listener, app)
                    .await
                    .expect("site actuator should serve");
            }));
        }
        handles
    }

    #[tokio::test]
    async fn create_snapshot_and_destroy_exact_child() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let child_path = dir.path().join("child.json5");
        write_file(
            &child_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["child"],
                network: { endpoints: [{ name: "out", port: 8080 }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
        );
        write_file(
            &root_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  program: {{ path: "/bin/echo", args: ["root"] }},
                  slots: {{
                    ctl: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{ manifest: "{child}" }}
                  }},
                }}
                "#,
                child = file_url(&child_path),
            ),
        );

        let mut state = compile_control_state(&root_path).await;
        let state_path = dir.path().join("control-state.json");
        write_control_state(&state_path, &state).expect("state should write");
        let root_authority = state.base_scenario.root;

        let response = create_child(
            &mut state,
            root_authority,
            CreateChildRequest {
                template: "worker".to_string(),
                name: "job-1".to_string(),
                manifest: None,
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
            &state_path,
        )
        .await
        .expect("create should succeed");

        assert_eq!(response.child.selector, "children.job-1");
        assert!(
            state
                .live_children
                .iter()
                .any(|child| child.name == "job-1")
        );

        let snapshot_response =
            snapshot(&state, state.base_scenario.root).expect("snapshot should succeed");
        let scenario_ir: ScenarioIr = serde_json::from_value(snapshot_response.scenario)
            .expect("snapshot scenario should decode");
        assert!(
            scenario_ir
                .components
                .iter()
                .any(|component| component.moniker == "/job-1"),
            "snapshot should contain the created child root"
        );

        destroy_child(&mut state, root_authority, "job-1", &state_path)
            .await
            .expect("destroy should succeed");
        assert!(
            state.live_children.is_empty(),
            "destroy should remove the live child record"
        );
        let snapshot_response =
            snapshot(&state, state.base_scenario.root).expect("snapshot should succeed");
        let scenario_ir: ScenarioIr = serde_json::from_value(snapshot_response.scenario)
            .expect("snapshot scenario should decode");
        assert!(
            !scenario_ir
                .components
                .iter()
                .any(|component| component.moniker == "/job-1"),
            "destroyed child should be absent from snapshots"
        );
    }

    #[tokio::test]
    async fn open_template_selection_uses_requested_catalog_key() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let alpha_path = dir.path().join("alpha.json5");
        let beta_path = dir.path().join("beta.json5");
        write_file(
            &alpha_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["alpha"],
                network: { endpoints: [{ name: "out", port: 8080 }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
        );
        write_file(
            &beta_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["beta"],
                network: { endpoints: [{ name: "out", port: 8080 }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
        );
        write_file(
            &root_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  program: {{ path: "/bin/echo", args: ["root"] }},
                  slots: {{
                    ctl: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{
                      allowed_manifests: ["{alpha}", "{beta}"]
                    }}
                  }},
                }}
                "#,
                alpha = file_url(&alpha_path),
                beta = file_url(&beta_path),
            ),
        );

        let mut state = compile_control_state(&root_path).await;
        let state_path = dir.path().join("control-state.json");
        write_control_state(&state_path, &state).expect("state should write");
        let beta_key = file_url(&beta_path);
        let root_authority = state.base_scenario.root;

        create_child(
            &mut state,
            root_authority,
            CreateChildRequest {
                template: "worker".to_string(),
                name: "job-open".to_string(),
                manifest: Some(
                    amber_mesh::component_protocol::CreateChildManifestSelection {
                        catalog_key: beta_key.clone(),
                    },
                ),
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
            &state_path,
        )
        .await
        .expect("open-template create should succeed");

        assert_eq!(
            state.live_children[0]
                .selected_manifest_catalog_key
                .as_deref(),
            Some(beta_key.as_str())
        );
        let snapshot_response =
            snapshot(&state, state.base_scenario.root).expect("snapshot should succeed");
        let scenario_ir: ScenarioIr = serde_json::from_value(snapshot_response.scenario)
            .expect("snapshot scenario should decode");
        let child = scenario_ir
            .components
            .iter()
            .find(|component| component.moniker == "/job-open")
            .expect("snapshot should contain the created child");
        let rendered_program =
            serde_json::to_string(&child.program).expect("program should encode");
        assert!(
            rendered_program.contains("beta"),
            "snapshot should contain the selected manifest, got {rendered_program}"
        );
    }

    #[tokio::test]
    async fn open_template_replay_uses_frozen_manifest_catalog_after_source_mutation() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let alpha_path = dir.path().join("alpha.json5");
        let beta_path = dir.path().join("beta.json5");
        write_file(
            &alpha_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["alpha-original"],
                network: { endpoints: [{ name: "out", port: 8081 }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
        );
        write_file(
            &beta_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["beta-original"],
                network: { endpoints: [{ name: "out", port: 8082 }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
        );
        write_file(
            &root_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{
                      allowed_manifests: ["{alpha}", "{beta}"]
                    }}
                  }},
                }}
                "#,
                alpha = file_url(&alpha_path),
                beta = file_url(&beta_path),
            ),
        );

        let mut state = compile_control_state(&root_path).await;
        let state_path = dir.path().join("control-state.json");
        write_control_state(&state_path, &state).expect("state should write");
        let root_authority = state.base_scenario.root;
        let beta_key = file_url(&beta_path);

        write_file(
            &beta_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["beta-mutated-on-disk"],
                network: { endpoints: [{ name: "out", port: 8082 }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
        );
        fs::remove_file(&alpha_path).expect("alpha source should be removable after compile");

        create_child(
            &mut state,
            root_authority,
            CreateChildRequest {
                template: "worker".to_string(),
                name: "job-open".to_string(),
                manifest: Some(
                    amber_mesh::component_protocol::CreateChildManifestSelection {
                        catalog_key: beta_key.clone(),
                    },
                ),
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
            &state_path,
        )
        .await
        .expect("open-template create should use the frozen catalog");

        let snapshot_response =
            snapshot(&state, root_authority).expect("snapshot should succeed after create");
        let scenario_ir: ScenarioIr = serde_json::from_value(snapshot_response.scenario.clone())
            .expect("snapshot scenario should decode");
        let created_child = scenario_ir
            .components
            .iter()
            .find(|component| component.moniker == "/job-open")
            .expect("snapshot should contain the created child");
        let created_program =
            serde_json::to_string(&created_child.program).expect("program should encode");
        assert!(
            created_program.contains("beta-original"),
            "snapshot should preserve the frozen selected manifest, got {created_program}"
        );
        assert!(
            !created_program.contains("beta-mutated-on-disk"),
            "snapshot must not reread the current disk manifest, got {created_program}"
        );

        fs::remove_file(&beta_path).expect("beta source should be removable before replay");

        let mut replayed = compile_control_state_from_snapshot(&snapshot_response).await;
        let replay_state_path = dir.path().join("replay-control-state.json");
        write_control_state(&replay_state_path, &replayed).expect("replay state should write");
        let replay_root_authority = replayed.base_scenario.root;

        create_child(
            &mut replayed,
            replay_root_authority,
            CreateChildRequest {
                template: "worker".to_string(),
                name: "job-replay".to_string(),
                manifest: Some(
                    amber_mesh::component_protocol::CreateChildManifestSelection {
                        catalog_key: file_url(&alpha_path),
                    },
                ),
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
            &replay_state_path,
        )
        .await
        .expect("replayed snapshot should preserve future dynamic create affordances");

        let replay_snapshot =
            snapshot(&replayed, replay_root_authority).expect("replay snapshot should succeed");
        let replay_ir: ScenarioIr = serde_json::from_value(replay_snapshot.scenario)
            .expect("replay scenario should decode");
        let replay_child = replay_ir
            .components
            .iter()
            .find(|component| component.moniker == "/job-replay")
            .expect("replay should contain the newly created child");
        let replay_program =
            serde_json::to_string(&replay_child.program).expect("program should encode");
        assert!(
            replay_program.contains("alpha-original"),
            "replay should still use the frozen manifest content, got {replay_program}"
        );
        assert!(
            !replay_program.contains("beta-mutated-on-disk"),
            "replay must not fall back to mutated on-disk content, got {replay_program}"
        );
    }

    #[tokio::test]
    async fn dynamic_framework_bindings_refresh_capability_instances_and_preserve_origin_realm() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let parent_path = dir.path().join("parent.json5");
        let worker_path = dir.path().join("worker.json5");
        let root_worker_path = dir.path().join("root-worker.json5");
        write_file(
            &worker_path,
            r#"
            {
              manifest_version: "0.3.0",
              slots: {
                realm: { kind: "component", optional: true }
              },
              program: {
                path: "/bin/echo",
                args: ["worker", "${slots.realm.url}"],
                network: { endpoints: [{ name: "http", port: 8080 }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
        );
        write_file(
            &root_worker_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["root-worker"],
                network: { endpoints: [{ name: "http", port: 8082 }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
        );
        write_file(
            &parent_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  program: {{
                    path: "/bin/echo",
                    args: ["parent", "${{slots.realm.url}}"],
                    network: {{ endpoints: [{{ name: "http", port: 8081 }}] }}
                  }},
                  provides: {{ http: {{ kind: "http", endpoint: "http" }} }},
                  exports: {{ http: "provides.http" }},
                  child_templates: {{
                    worker: {{
                      manifest: "{worker}",
                      bindings: {{
                        realm: "slots.realm"
                      }}
                    }}
                  }},
                }}
                "#,
                worker = file_url(&worker_path),
            ),
        );
        write_file(
            &root_path,
            &format!(
                r##"
                {{
                  manifest_version: "0.3.0",
                  program: {{ path: "/bin/echo", args: ["root"] }},
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    root_worker: {{
                      manifest: "{root_worker}"
                    }}
                  }},
                  components: {{
                    parent: "{parent}"
                  }},
                  bindings: [
                    {{ to: "#parent.realm", from: "framework.component" }}
                  ],
                  exports: {{
                    parent_http: "#parent.http"
                  }},
                }}
                "##,
                root_worker = file_url(&root_worker_path),
                parent = file_url(&parent_path),
            ),
        );

        let mut state = compile_control_state(&root_path).await;
        let state_path = dir.path().join("control-state.json");
        write_control_state(&state_path, &state).expect("state should write");
        let base = Scenario::try_from(state.base_scenario.clone()).expect("base scenario");
        let parent_id = base
            .components_iter()
            .find(|(_, component)| component.moniker.as_str() == "/parent")
            .map(|(id, _)| id.0)
            .expect("parent component should exist");
        let static_parent_record = state
            .capability_instances
            .values()
            .find(|record| record.recipient_component_moniker == "/parent")
            .cloned()
            .expect("static parent should have a realm capability instance");
        assert_eq!(static_parent_record.authority_realm_moniker, "/");

        create_child(
            &mut state,
            parent_id,
            CreateChildRequest {
                template: "worker".to_string(),
                name: "delegate".to_string(),
                manifest: None,
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
            &state_path,
        )
        .await
        .expect("delegate child should be created");

        let dynamic_record = state
            .capability_instances
            .values()
            .find(|record| record.recipient_component_moniker == "/parent/delegate")
            .cloned()
            .expect("dynamic child should receive its own realm capability instance");
        let root_authority = state.base_scenario.root;
        assert_eq!(dynamic_record.authority_realm_id, root_authority);
        assert_eq!(dynamic_record.authority_realm_moniker, "/");
        let authorized = authorize_capability_instance(
            &state,
            &dynamic_record.cap_instance_id,
            "/parent/delegate",
        )
        .expect("dynamic child capability instance should authorize for its own peer");
        let delegated_authority_realm_id = authorized.authority_realm_id;
        assert_eq!(delegated_authority_realm_id, root_authority);

        create_child(
            &mut state,
            delegated_authority_realm_id,
            CreateChildRequest {
                template: "root_worker".to_string(),
                name: "sibling".to_string(),
                manifest: None,
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
            &state_path,
        )
        .await
        .expect("forwarded realm authority should create a sibling in the parent realm");

        let live_scenario = live_scenario_ir(&state).expect("live scenario should materialize");
        let live = Scenario::try_from(live_scenario).expect("live scenario should decode");
        assert!(
            live.components_iter()
                .any(|(_, component)| component.moniker.as_str() == "/parent/delegate"),
            "delegate should live under the parent realm"
        );
        assert!(
            live.components_iter()
                .any(|(_, component)| component.moniker.as_str() == "/sibling"),
            "forwarded realm capability should create in the origin realm, not under the caller"
        );

        destroy_child(&mut state, parent_id, "delegate", &state_path)
            .await
            .expect("destroy should succeed");
        assert!(
            !state
                .capability_instances
                .values()
                .any(|record| record.recipient_component_moniker == "/parent/delegate"),
            "destroy should revoke dynamic capability instances owned by the removed child"
        );
    }

    #[tokio::test]
    async fn capability_instance_auth_and_snapshot_scope_are_enforced() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let parent_path = dir.path().join("parent.json5");
        write_file(
            &parent_path,
            r#"
            {
              manifest_version: "0.3.0",
              slots: {
                realm: { kind: "component", optional: true }
              },
              program: {
                path: "/bin/echo",
                args: ["parent", "${slots.realm.url}"],
                network: { endpoints: [{ name: "http", port: 8081 }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
        );
        write_file(
            &root_path,
            &format!(
                r##"
                {{
                  manifest_version: "0.3.0",
                  program: {{ path: "/bin/echo", args: ["root"] }},
                  components: {{
                    parent: "{parent}"
                  }},
                  bindings: [
                    {{ to: "#parent.realm", from: "framework.component" }}
                  ],
                  exports: {{
                    parent_http: "#parent.http"
                  }},
                }}
                "##,
                parent = file_url(&parent_path),
            ),
        );

        let state = compile_control_state(&root_path).await;
        let base = Scenario::try_from(state.base_scenario.clone()).expect("base scenario");
        let parent_id = base
            .components_iter()
            .find(|(_, component)| component.moniker.as_str() == "/parent")
            .map(|(id, _)| id.0)
            .expect("parent component should exist");
        let record = state
            .capability_instances
            .values()
            .find(|record| record.recipient_component_moniker == "/parent")
            .expect("parent should have a realm capability instance");

        let wrong_peer = authorize_capability_instance(&state, &record.cap_instance_id, "/root")
            .expect_err("peer mismatch should be rejected");
        assert_eq!(wrong_peer.code, ProtocolErrorCode::Unauthorized);

        let unknown = authorize_capability_instance(&state, "cap.missing", "/parent")
            .expect_err("unknown capability instance should be rejected");
        assert_eq!(unknown.code, ProtocolErrorCode::Unauthorized);

        let snapshot_err = snapshot(&state, parent_id)
            .expect_err("non-root authority should not be able to snapshot");
        assert_eq!(snapshot_err.code, ProtocolErrorCode::ScopeNotAllowed);
    }

    #[tokio::test]
    async fn create_rejects_duplicate_names_and_destroy_is_idempotent() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let child_path = dir.path().join("child.json5");
        write_file(
            &child_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["child"],
                network: { endpoints: [{ name: "out", port: 8080 }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
        );
        write_file(
            &root_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{ manifest: "{child}" }}
                  }},
                }}
                "#,
                child = file_url(&child_path),
            ),
        );

        let mut state = compile_control_state(&root_path).await;
        let state_path = dir.path().join("control-state.json");
        write_control_state(&state_path, &state).expect("state should write");
        let root_authority = state.base_scenario.root;

        create_child(
            &mut state,
            root_authority,
            CreateChildRequest {
                template: "worker".to_string(),
                name: "job".to_string(),
                manifest: None,
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
            &state_path,
        )
        .await
        .expect("first create should succeed");

        let duplicate = create_child(
            &mut state,
            root_authority,
            CreateChildRequest {
                template: "worker".to_string(),
                name: "job".to_string(),
                manifest: None,
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
            &state_path,
        )
        .await
        .expect_err("duplicate child name should be rejected");
        assert_eq!(duplicate.code, ProtocolErrorCode::NameConflict);

        destroy_child(&mut state, root_authority, "job", &state_path)
            .await
            .expect("first destroy should succeed");
        destroy_child(&mut state, root_authority, "job", &state_path)
            .await
            .expect("destroy should be idempotent once the child is gone");
        assert!(
            state.live_children.is_empty(),
            "destroy should remove the child"
        );
    }

    #[tokio::test]
    async fn create_rejects_unoffered_backend_without_committing_child_state() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let direct_child_path = dir.path().join("child-direct.json5");
        let compose_child_path = dir.path().join("child-compose.json5");
        write_file(
            &direct_child_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["direct-only"],
                network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
        );
        write_file(
            &compose_child_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                image: "busybox:1.36.1",
                entrypoint: ["/bin/sh", "-c", "sleep 1"],
                network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
        );
        write_file(
            &root_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{
                      allowed_manifests: ["{compose_child}", "{direct_child}"]
                    }}
                  }},
                }}
                "#,
                compose_child = file_url(&compose_child_path),
                direct_child = file_url(&direct_child_path),
            ),
        );
        let compiler = Compiler::new(Resolver::new(), DigestStore::default());
        let output = compiler
            .compile(
                ManifestRef::from_url(
                    Url::from_file_path(&root_path).expect("root path should convert to URL"),
                ),
                CompileOptions::default(),
            )
            .await
            .expect("fixture should compile");
        let compiled = CompiledScenario::from_compile_output(&output)
            .expect("fixture should materialize compiled scenario");
        let placement = PlacementFile {
            schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
            version: amber_compiler::run_plan::PLACEMENT_VERSION,
            sites: BTreeMap::from([(
                "compose_local".to_string(),
                SiteDefinition {
                    kind: SiteKind::Compose,
                    context: None,
                },
            )]),
            defaults: PlacementDefaults {
                image: Some("compose_local".to_string()),
                ..PlacementDefaults::default()
            },
            components: BTreeMap::new(),
        };
        let err = build_run_plan(&compiled, Some(&placement))
            .expect_err("run planning should reject future direct children without a direct site");
        let message = err.to_string();
        assert!(
            message.contains("program.path"),
            "placement failure should point operators at the missing future direct site, got \
             {message}"
        );
    }

    #[tokio::test]
    async fn concurrent_same_name_creates_serialize_to_one_live_child() {
        let (dir, state, state_path) = compile_exact_template_control_state().await;
        let root_authority = state.base_scenario.root;
        let app = test_control_state_app(&dir, state, state_path);
        let actuators = install_success_site_actuator(&app).await;
        let request = CreateChildRequest {
            template: "worker".to_string(),
            name: "job".to_string(),
            manifest: None,
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
        };

        let (left, right) = tokio::join!(
            execute_create_child(&app, root_authority, request.clone()),
            execute_create_child(&app, root_authority, request),
        );
        let results = [left, right];
        assert_eq!(
            results.iter().filter(|result| result.is_ok()).count(),
            1,
            "exactly one racing create should succeed",
        );
        assert_eq!(
            results
                .iter()
                .filter_map(|result| result.as_ref().err())
                .filter(|err| err.0.code == ProtocolErrorCode::NameConflict)
                .count(),
            1,
            "exactly one racing create should fail with name_conflict",
        );

        let state = app.control_state.lock().await.clone();
        assert_eq!(
            state.live_children.len(),
            1,
            "only one child should be committed"
        );
        assert_eq!(state.live_children[0].name, "job");
        let snapshot_response =
            snapshot(&state, root_authority).expect("snapshot should succeed after the race");
        let scenario_ir: ScenarioIr = serde_json::from_value(snapshot_response.scenario)
            .expect("snapshot scenario should decode");
        assert_eq!(
            scenario_ir
                .components
                .iter()
                .filter(|component| component.moniker == "/job")
                .count(),
            1,
            "snapshot should remain clean after the same-name race",
        );
        for actuator in actuators {
            actuator.abort();
        }
    }

    #[tokio::test]
    async fn concurrent_distinct_creates_commit_both_children() {
        let (dir, state, state_path) = compile_exact_template_control_state().await;
        let root_authority = state.base_scenario.root;
        let app = test_control_state_app(&dir, state, state_path);
        let actuators = install_success_site_actuator(&app).await;

        let (left, right) = tokio::join!(
            execute_create_child(
                &app,
                root_authority,
                CreateChildRequest {
                    template: "worker".to_string(),
                    name: "job-a".to_string(),
                    manifest: None,
                    config: BTreeMap::new(),
                    bindings: BTreeMap::new(),
                },
            ),
            execute_create_child(
                &app,
                root_authority,
                CreateChildRequest {
                    template: "worker".to_string(),
                    name: "job-b".to_string(),
                    manifest: None,
                    config: BTreeMap::new(),
                    bindings: BTreeMap::new(),
                },
            ),
        );
        left.expect("first distinct create should succeed");
        right.expect("second distinct create should succeed");

        let state = app.control_state.lock().await.clone();
        assert_eq!(
            state.live_children.len(),
            2,
            "both children should be committed"
        );
        assert_eq!(
            state
                .live_children
                .iter()
                .map(|child| child.name.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["job-a", "job-b"]),
        );
        let snapshot_response =
            snapshot(&state, root_authority).expect("snapshot should succeed after both creates");
        let scenario_ir: ScenarioIr = serde_json::from_value(snapshot_response.scenario)
            .expect("snapshot scenario should decode");
        assert!(
            scenario_ir
                .components
                .iter()
                .any(|component| component.moniker == "/job-a"),
            "snapshot should contain the first child",
        );
        assert!(
            scenario_ir
                .components
                .iter()
                .any(|component| component.moniker == "/job-b"),
            "snapshot should contain the second child",
        );
        for actuator in actuators {
            actuator.abort();
        }
    }

    #[tokio::test]
    async fn prepare_child_record_uses_frozen_dynamic_placement_assignments() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let child_path = dir.path().join("child.json5");
        write_file(
            &child_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                image: "busybox:1.36.1",
                entrypoint: ["/bin/sh", "-c", "sleep 1"],
                network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
        );
        write_file(
            &root_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{ manifest: "{child}" }}
                  }},
                }}
                "#,
                child = file_url(&child_path),
            ),
        );

        let placement = PlacementFile {
            schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
            version: amber_compiler::run_plan::PLACEMENT_VERSION,
            sites: BTreeMap::from([
                (
                    "compose_local".to_string(),
                    SiteDefinition {
                        kind: SiteKind::Compose,
                        context: None,
                    },
                ),
                (
                    "kind_local".to_string(),
                    SiteDefinition {
                        kind: SiteKind::Kubernetes,
                        context: None,
                    },
                ),
            ]),
            defaults: PlacementDefaults {
                image: Some("compose_local".to_string()),
                ..PlacementDefaults::default()
            },
            components: BTreeMap::from([("/job".to_string(), "kind_local".to_string())]),
        };

        let mut state = compile_control_state_with_placement(&root_path, Some(&placement)).await;
        let root_authority = state.base_scenario.root;
        let child = prepare_child_record(
            &mut state,
            root_authority,
            &CreateChildRequest {
                template: "worker".to_string(),
                name: "job".to_string(),
                manifest: None,
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
        )
        .await
        .expect("child should plan successfully");

        assert_eq!(
            child.assignments.get("/job").map(String::as_str),
            Some("kind_local"),
            "dynamic create must honor frozen placement entries for future child monikers",
        );
    }

    #[tokio::test]
    async fn prepare_child_record_preserves_cross_backend_matrix_assignments() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let child_path = dir.path().join("child-compose.json5");
        let child_root_path = dir.path().join("child-compose-root.json5");
        let direct_helper_path = dir.path().join("direct-helper.json5");
        let kind_helper_path = dir.path().join("kind-helper.json5");
        let vm_helper_path = dir.path().join("vm-helper.json5");
        let vm_helper_root_path = dir.path().join("vm-helper-root.json5");

        write_file(
            &direct_helper_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/sh",
                args: ["-c", "sleep 1"],
                network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
        );
        write_file(
            &kind_helper_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                image: "busybox:1.36.1",
                entrypoint: ["/bin/sh", "-c", "sleep 1"],
                network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
        );
        write_file(
            &vm_helper_root_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                vm: {
                  image: "/tmp/base.img",
                  cpus: 1,
                  memory_mib: 256,
                  cloud_init: {
                    user_data: "IyBjbG91ZC1jb25maWcK"
                  },
                  network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
                }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
        );
        write_file(
            &vm_helper_path,
            &format!(
                r##"
                {{
                  manifest_version: "0.3.0",
                  components: {{
                    root: "{vm_helper_root}"
                  }},
                  exports: {{
                    http: "#root.http"
                  }}
                }}
                "##,
                vm_helper_root = file_url(&vm_helper_root_path),
            ),
        );
        write_file(
            &child_root_path,
            r#"
            {
              manifest_version: "0.3.0",
              slots: {
                direct: { kind: "http" },
                kind: { kind: "http" },
                vm: { kind: "http" }
              },
              program: {
                image: "busybox:1.36.1",
                entrypoint: ["/bin/sh", "-c", "sleep 1"],
                env: {
                  DIRECT_URL: "${slots.direct.url}",
                  KIND_URL: "${slots.kind.url}",
                  VM_URL: "${slots.vm.url}"
                },
                network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
        );
        write_file(
            &child_path,
            &format!(
                r##"
                {{
                  manifest_version: "0.3.0",
                  components: {{
                    direct_helper: "{direct_helper}",
                    kind_helper: "{kind_helper}",
                    root: "{child_root}",
                    vm_helper: "{vm_helper}"
                  }},
                  bindings: [
                    {{ from: "#kind_helper.http", to: "#root.kind" }},
                    {{ from: "#direct_helper.http", to: "#root.direct" }},
                    {{ from: "#vm_helper.http", to: "#root.vm" }}
                  ],
                  exports: {{
                    direct_http: "#direct_helper.http",
                    http: "#root.http",
                    kind_http: "#kind_helper.http",
                    vm_http: "#vm_helper.http"
                  }}
                }}
                "##,
                direct_helper = file_url(&direct_helper_path),
                kind_helper = file_url(&kind_helper_path),
                child_root = file_url(&child_root_path),
                vm_helper = file_url(&vm_helper_path),
            ),
        );
        write_file(
            &root_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    child_compose: {{ manifest: "{child}" }}
                  }},
                }}
                "#,
                child = file_url(&child_path),
            ),
        );

        let placement = PlacementFile {
            schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
            version: amber_compiler::run_plan::PLACEMENT_VERSION,
            sites: BTreeMap::from([
                (
                    "compose_local".to_string(),
                    SiteDefinition {
                        kind: SiteKind::Compose,
                        context: None,
                    },
                ),
                (
                    "direct_local".to_string(),
                    SiteDefinition {
                        kind: SiteKind::Direct,
                        context: None,
                    },
                ),
                (
                    "kind_local".to_string(),
                    SiteDefinition {
                        kind: SiteKind::Kubernetes,
                        context: None,
                    },
                ),
                (
                    "vm_local".to_string(),
                    SiteDefinition {
                        kind: SiteKind::Vm,
                        context: None,
                    },
                ),
            ]),
            defaults: PlacementDefaults {
                image: Some("compose_local".to_string()),
                path: Some("direct_local".to_string()),
                vm: Some("vm_local".to_string()),
            },
            components: BTreeMap::from([
                ("/job-compose/root".to_string(), "compose_local".to_string()),
                (
                    "/job-compose/kind_helper".to_string(),
                    "kind_local".to_string(),
                ),
                (
                    "/job-compose/direct_helper".to_string(),
                    "direct_local".to_string(),
                ),
                ("/job-compose/vm_helper".to_string(), "vm_local".to_string()),
            ]),
        };

        let mut state = compile_control_state_with_placement(&root_path, Some(&placement)).await;
        let root_authority = state.base_scenario.root;
        let child = prepare_child_record(
            &mut state,
            root_authority,
            &CreateChildRequest {
                template: "child_compose".to_string(),
                name: "job-compose".to_string(),
                manifest: None,
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
        )
        .await
        .expect("matrix child should plan successfully");

        assert_eq!(
            child
                .assignments
                .get("/job-compose/root")
                .map(String::as_str),
            Some("compose_local"),
        );
        assert_eq!(
            child
                .assignments
                .get("/job-compose/kind_helper")
                .map(String::as_str),
            Some("kind_local"),
        );
        assert_eq!(
            child
                .assignments
                .get("/job-compose/direct_helper")
                .map(String::as_str),
            Some("direct_local"),
        );
        assert_eq!(
            child
                .assignments
                .get("/job-compose/vm_helper/root")
                .map(String::as_str),
            Some("vm_local"),
        );
        assert_eq!(
            child
                .site_plans
                .iter()
                .map(|site_plan| site_plan.site_id.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["compose_local", "direct_local", "kind_local", "vm_local"]),
            "cross-backend child planning should retain all expected site slices",
        );
        let proxy_exports_by_site = child
            .site_plans
            .iter()
            .map(|site_plan| {
                (
                    site_plan.site_id.as_str(),
                    site_plan
                        .proxy_exports
                        .keys()
                        .map(String::as_str)
                        .collect::<BTreeSet<_>>(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            proxy_exports_by_site.get("compose_local"),
            Some(&BTreeSet::from(["http"])),
            "compose site should own the dynamic child root export",
        );
        for (site_id, public_export) in [
            ("kind_local", "kind_http"),
            ("direct_local", "direct_http"),
            ("vm_local", "vm_http"),
        ] {
            let exports = proxy_exports_by_site
                .get(site_id)
                .unwrap_or_else(|| panic!("missing proxy export set for {site_id}"));
            assert!(
                exports.contains(public_export),
                "{site_id} should keep its public helper export",
            );
            assert!(
                exports.iter().any(|name| name.starts_with("amber_export_")),
                "{site_id} should also publish its internal routed link export",
            );
        }
    }

    #[tokio::test]
    async fn describe_template_exposes_dynamic_child_exports_as_binding_candidates() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let producer_path = dir.path().join("producer.json5");
        let consumer_path = dir.path().join("consumer.json5");
        write_file(
            &producer_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["producer"],
                network: { endpoints: [{ name: "out", port: 8080 }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
        );
        write_file(
            &consumer_path,
            r#"
            {
              manifest_version: "0.3.0",
              slots: {
                upstream: { kind: "http" }
              },
              program: {
                path: "/bin/echo",
                args: ["consumer", "${slots.upstream.url}"]
              },
            }
            "#,
        );
        write_file(
            &root_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    producer: {{ manifest: "{producer}" }},
                    consumer: {{ manifest: "{consumer}" }}
                  }},
                }}
                "#,
                producer = file_url(&producer_path),
                consumer = file_url(&consumer_path),
            ),
        );

        let mut state = compile_control_state(&root_path).await;
        let state_path = dir.path().join("control-state.json");
        write_control_state(&state_path, &state).expect("state should write");
        let root_authority = state.base_scenario.root;

        create_child(
            &mut state,
            root_authority,
            CreateChildRequest {
                template: "producer".to_string(),
                name: "source".to_string(),
                manifest: None,
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
            &state_path,
        )
        .await
        .expect("producer child should be created");

        let description =
            describe_template(&state, root_authority, "consumer").expect("template should exist");
        let upstream = description
            .bindings
            .get("upstream")
            .expect("consumer should expose the upstream binding");
        assert_eq!(upstream.state, InputState::Open);
        assert!(
            upstream
                .candidates
                .iter()
                .any(|candidate| candidate == "children.source.exports.out"),
            "dynamic child exports should enter the authority realm bindable source set"
        );
    }

    #[tokio::test]
    async fn describe_template_exposes_static_child_exports_as_binding_candidates() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let provider_path = dir.path().join("provider.json5");
        let consumer_path = dir.path().join("consumer.json5");
        write_file(
            &provider_path,
            r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["provider"],
                network: { endpoints: [{ name: "out", port: 8080 }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
        );
        write_file(
            &consumer_path,
            r#"
            {
              manifest_version: "0.3.0",
              slots: {
                upstream: { kind: "http" }
              },
              program: {
                path: "/bin/echo",
                args: ["consumer", "${slots.upstream.url}"]
              },
            }
            "#,
        );
        write_file(
            &root_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  components: {{
                    provider: "{provider}"
                  }},
                  child_templates: {{
                    consumer: {{ manifest: "{consumer}" }}
                  }},
                }}
                "#,
                provider = file_url(&provider_path),
                consumer = file_url(&consumer_path),
            ),
        );

        let state = compile_control_state(&root_path).await;
        let description = describe_template(&state, state.base_scenario.root, "consumer")
            .expect("template should exist");
        let upstream = description
            .bindings
            .get("upstream")
            .expect("consumer should expose the upstream binding");
        assert_eq!(upstream.state, InputState::Open);
        assert!(
            upstream
                .candidates
                .iter()
                .any(|candidate| candidate == "children.provider.exports.out"),
            "static child exports should enter the authority realm bindable source set"
        );
    }

    #[tokio::test]
    async fn root_external_bindable_sources_are_listed_and_weak() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let worker_path = dir.path().join("worker.json5");
        write_file(
            &worker_path,
            r#"
            {
              manifest_version: "0.3.0",
              slots: {
                catalog_api: { kind: "http" }
              },
              program: {
                path: "/bin/echo",
                args: ["worker", "${slots.catalog_api.url}"]
              }
            }
            "#,
        );
        write_file(
            &root_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }},
                    catalog_api: {{ kind: "http" }}
                  }},
                  program: {{
                    path: "/bin/echo",
                    args: ["root"]
                  }},
                  child_templates: {{
                    worker: {{
                      manifest: "{worker}"
                    }}
                  }}
                }}
                "#,
                worker = file_url(&worker_path),
            ),
        );

        let state = compile_control_state(&root_path).await;
        let scenario = Scenario::try_from(state.base_scenario.clone()).expect("base scenario");
        let candidates =
            bindable_source_candidates(&scenario, &state.base_scenario, &state, scenario.root)
                .expect("candidates");
        let external = candidates
            .iter()
            .find(|candidate| candidate.selector == "external.catalog_api")
            .expect("root external source should be listed");
        assert_eq!(external.sources.len(), 1);
        assert!(
            external.sources[0].weak,
            "root external bindable sources must remain weak because they depend on the external \
             site"
        );
    }

    #[tokio::test]
    async fn open_template_rejects_manifest_outside_frozen_allowed_set() {
        let dir = TempDir::new().expect("temp dir");
        let root_path = dir.path().join("root.json5");
        let alpha_path = dir.path().join("alpha.json5");
        let beta_path = dir.path().join("beta.json5");
        let gamma_path = dir.path().join("gamma.json5");
        for (path, label) in [
            (&alpha_path, "alpha"),
            (&beta_path, "beta"),
            (&gamma_path, "gamma"),
        ] {
            write_file(
                path,
                &format!(
                    r#"
                    {{
                      manifest_version: "0.3.0",
                      program: {{ path: "/bin/echo", args: ["{label}"] }},
                    }}
                    "#
                ),
            );
        }
        write_file(
            &root_path,
            &format!(
                r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{
                      allowed_manifests: ["{alpha}", "{beta}"]
                    }}
                  }},
                }}
                "#,
                alpha = file_url(&alpha_path),
                beta = file_url(&beta_path),
            ),
        );

        let mut state = compile_control_state(&root_path).await;
        let state_path = dir.path().join("control-state.json");
        write_control_state(&state_path, &state).expect("state should write");
        let root_authority = state.base_scenario.root;

        let err = create_child(
            &mut state,
            root_authority,
            CreateChildRequest {
                template: "worker".to_string(),
                name: "job".to_string(),
                manifest: Some(
                    amber_mesh::component_protocol::CreateChildManifestSelection {
                        catalog_key: file_url(&gamma_path),
                    },
                ),
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
            &state_path,
        )
        .await
        .expect_err("unexpected manifest selection should be rejected");
        assert_eq!(err.code, ProtocolErrorCode::ManifestNotAllowed);
    }

    #[tokio::test]
    async fn execute_create_child_write_failure_rolls_back_authoritative_state() {
        let (dir, state, _) = compile_exact_template_control_state().await;
        let bad_state_path = dir.path().join("control-state-dir");
        fs::create_dir_all(&bad_state_path).expect("bad state path should exist as a directory");
        let root_authority = state.base_scenario.root;
        let app = test_control_state_app(&dir, state, bad_state_path);

        let err = execute_create_child(
            &app,
            root_authority,
            CreateChildRequest {
                template: "worker".to_string(),
                name: "job".to_string(),
                manifest: None,
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
        )
        .await
        .expect_err("create should fail when control-state writes fail");
        assert_eq!(err.0.code, ProtocolErrorCode::ControlStateUnavailable);

        let recovered = app.control_state.lock().await.clone();
        assert!(
            recovered.live_children.is_empty(),
            "failed create must not leave an in-memory child record behind"
        );
        assert!(
            recovered.journal.is_empty(),
            "failed create must not append durable journal entries in memory"
        );
    }

    #[tokio::test]
    async fn execute_destroy_child_write_failure_preserves_live_state() {
        let (dir, mut state, state_path) = compile_exact_template_control_state().await;
        let root_authority = state.base_scenario.root;
        create_child(
            &mut state,
            root_authority,
            CreateChildRequest {
                template: "worker".to_string(),
                name: "job".to_string(),
                manifest: None,
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
            &state_path,
        )
        .await
        .expect("setup create should succeed");

        let bad_state_path = dir.path().join("control-state-dir");
        fs::create_dir_all(&bad_state_path).expect("bad state path should exist as a directory");
        let app = test_control_state_app(&dir, state, bad_state_path);

        let err = execute_destroy_child(&app, root_authority, "job")
            .await
            .expect_err("destroy should fail when control-state writes fail");
        assert_eq!(err.0.code, ProtocolErrorCode::ControlStateUnavailable);

        let recovered = app.control_state.lock().await.clone();
        let live_child = recovered
            .live_children
            .iter()
            .find(|child| child.name == "job")
            .expect("failed destroy must keep the live child present");
        assert_eq!(live_child.state, ChildState::Live);
    }

    #[tokio::test]
    async fn recover_control_state_aborts_create_requested_children() {
        let (dir, mut state, state_path) = compile_empty_control_state().await;
        let root_authority = state.base_scenario.root;
        state.live_children.push(empty_live_child(
            root_authority,
            "requested",
            1,
            ChildState::CreateRequested,
        ));
        write_control_state(&state_path, &state).expect("state should write");
        let app = test_control_state_app(&dir, state, state_path);

        recover_control_state(&app)
            .await
            .expect("recovery should succeed");

        let recovered = app.control_state.lock().await.clone();
        assert!(
            recovered.live_children.is_empty(),
            "create_requested recovery should discard the stale child"
        );
        assert_eq!(
            recovered.journal.last().map(|entry| entry.state),
            Some(ChildState::CreateAborted)
        );
    }

    #[tokio::test]
    async fn recover_control_state_aborts_create_prepared_children() {
        let (dir, mut state, state_path) = compile_empty_control_state().await;
        let root_authority = state.base_scenario.root;
        state.live_children.push(empty_live_child(
            root_authority,
            "prepared",
            1,
            ChildState::CreatePrepared,
        ));
        write_control_state(&state_path, &state).expect("state should write");
        let app = test_control_state_app(&dir, state, state_path);

        recover_control_state(&app)
            .await
            .expect("recovery should succeed");

        let recovered = app.control_state.lock().await.clone();
        assert!(
            recovered.live_children.is_empty(),
            "create_prepared recovery should remove the child"
        );
        assert_eq!(
            recovered.journal.last().map(|entry| entry.state),
            Some(ChildState::CreateAborted)
        );
    }

    #[tokio::test]
    async fn recover_control_state_promotes_create_committed_hidden_children_to_live() {
        let (dir, mut state, state_path) = compile_empty_control_state().await;
        let root_authority = state.base_scenario.root;
        state.live_children.push(empty_live_child(
            root_authority,
            "hidden",
            1,
            ChildState::CreateCommittedHidden,
        ));
        write_control_state(&state_path, &state).expect("state should write");
        let app = test_control_state_app(&dir, state, state_path);

        recover_control_state(&app)
            .await
            .expect("recovery should succeed");

        let recovered = app.control_state.lock().await.clone();
        assert_eq!(
            recovered
                .live_children
                .iter()
                .find(|child| child.name == "hidden")
                .map(|child| child.state),
            Some(ChildState::Live)
        );
        assert_eq!(
            recovered.journal.last().map(|entry| entry.state),
            Some(ChildState::Live)
        );
    }

    #[tokio::test]
    async fn recover_control_state_completes_destroy_requested_children() {
        let (dir, mut state, state_path) = compile_empty_control_state().await;
        let root_authority = state.base_scenario.root;
        state.live_children.push(empty_live_child(
            root_authority,
            "doomed",
            1,
            ChildState::DestroyRequested,
        ));
        write_control_state(&state_path, &state).expect("state should write");
        let app = test_control_state_app(&dir, state, state_path);

        recover_control_state(&app)
            .await
            .expect("recovery should succeed");

        let recovered = app.control_state.lock().await.clone();
        assert!(
            recovered.live_children.is_empty(),
            "destroy_requested recovery should commit the removal"
        );
        let states = recovered
            .journal
            .iter()
            .map(|entry| entry.state)
            .collect::<Vec<_>>();
        assert!(
            states.contains(&ChildState::DestroyRetracted),
            "recovery should retract bindings before commit"
        );
        assert_eq!(states.last().copied(), Some(ChildState::DestroyCommitted));
    }

    #[tokio::test]
    async fn recover_control_state_completes_destroy_retracted_children() {
        let (dir, mut state, state_path) = compile_empty_control_state().await;
        let root_authority = state.base_scenario.root;
        state.live_children.push(empty_live_child(
            root_authority,
            "retracted",
            1,
            ChildState::DestroyRetracted,
        ));
        write_control_state(&state_path, &state).expect("state should write");
        let app = test_control_state_app(&dir, state, state_path);

        recover_control_state(&app)
            .await
            .expect("recovery should succeed");

        let recovered = app.control_state.lock().await.clone();
        assert!(
            recovered.live_children.is_empty(),
            "destroy_retracted recovery should commit the removal"
        );
        assert_eq!(
            recovered.journal.last().map(|entry| entry.state),
            Some(ChildState::DestroyCommitted)
        );
    }
}
