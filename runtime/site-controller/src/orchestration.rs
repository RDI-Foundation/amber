#[cfg(target_os = "linux")]
use std::net::Ipv4Addr;

use amber_mesh::{
    InboundRoute, InboundTarget, MeshConfigPublic, MeshPeer, OutboundRoute,
    router_external_route_id,
};

use super::{http::*, planner::*, state::*, *};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SiteControllerPrepareRequest {
    pub(crate) site_plan: DynamicSitePlanRecord,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SiteControllerPublishRequest {
    pub(crate) site_plan: DynamicSitePlanRecord,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct SiteControllerDestroyRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) desired_site_plan: Option<DynamicSitePlanRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct ControlCreateChildRequest {
    pub(super) cap_instance_id: String,
    pub(super) request: CreateChildRequest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct ControlDestroyChildRequest {
    pub(super) cap_instance_id: String,
}

#[derive(Debug)]
pub(super) struct ProtocolApiError(pub(super) ProtocolErrorResponse);

impl ProtocolApiError {
    pub(super) fn control_state_unavailable(message: impl Into<String>) -> Self {
        Self(ProtocolErrorResponse {
            code: ProtocolErrorCode::ControlStateUnavailable,
            message: message.into(),
            details: None,
        })
    }

    pub(super) fn unauthorized(message: impl Into<String>) -> Self {
        Self(ProtocolErrorResponse {
            code: ProtocolErrorCode::Unauthorized,
            message: message.into(),
            details: None,
        })
    }

    pub(super) fn status_code(&self) -> StatusCode {
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
            ProtocolErrorCode::UnknownSource
            | ProtocolErrorCode::UnknownRef
            | ProtocolErrorCode::UnknownHandle => StatusCode::NOT_FOUND,
            ProtocolErrorCode::IdempotencyConflict | ProtocolErrorCode::AlreadyRevoked => {
                StatusCode::CONFLICT
            }
            ProtocolErrorCode::CallerLacksAuthority | ProtocolErrorCode::RecipientMismatch => {
                StatusCode::FORBIDDEN
            }
            ProtocolErrorCode::OriginUnavailable | ProtocolErrorCode::PathEstablishmentFailed => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            ProtocolErrorCode::ManifestRequired
            | ProtocolErrorCode::ManifestNotAllowed
            | ProtocolErrorCode::InvalidManifestRef
            | ProtocolErrorCode::ManifestDigestMismatch
            | ProtocolErrorCode::ManifestResolutionFailed
            | ProtocolErrorCode::InvalidConfig
            | ProtocolErrorCode::InvalidBinding
            | ProtocolErrorCode::BindingTypeMismatch
            | ProtocolErrorCode::PlacementUnsatisfied
            | ProtocolErrorCode::SiteNotActive
            | ProtocolErrorCode::ScopeNotAllowed
            | ProtocolErrorCode::AmbiguousSource
            | ProtocolErrorCode::RevokedSource
            | ProtocolErrorCode::UnknownRecipientIdentity
            | ProtocolErrorCode::RecipientNotLive
            | ProtocolErrorCode::MandatoryNoop
            | ProtocolErrorCode::AuthorityPathUnavailable
            | ProtocolErrorCode::MalformedRef
            | ProtocolErrorCode::RevokedRef
            | ProtocolErrorCode::HandleNotDynamic => StatusCode::BAD_REQUEST,
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

pub(super) fn control_state_step_error(
    step: &str,
    err: impl std::fmt::Display,
) -> ProtocolErrorResponse {
    protocol_error(
        ProtocolErrorCode::ControlStateUnavailable,
        &format!("failed to persist {step}: {err}"),
    )
}

pub(super) fn controller_protocol_error(
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

pub(super) fn site_state_root_for(app: &ControlStateApp, site_id: &str) -> PathBuf {
    Path::new(&app.state_root).join(site_id)
}

pub(super) fn site_controller_plan_path_for_site(app: &ControlStateApp, site_id: &str) -> PathBuf {
    site_controller_plan_path(&site_state_root_for(app, site_id))
}

pub(super) fn site_receipt_from_manager_state(state: &SiteManagerStateView) -> SiteReceipt {
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
        site_controller_pid: state.site_controller_pid,
        site_controller_url: state.site_controller_url.clone(),
    }
}

pub(super) fn full_site_plan_record(
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

pub(super) fn desired_site_plan_map(
    state: &FrameworkControlState,
    site_ids: &BTreeSet<String>,
) -> std::result::Result<BTreeMap<String, DynamicSitePlanRecord>, ProtocolErrorResponse> {
    let planned = build_site_plan_subset(
        &decode_live_scenario(state)?,
        &placement_file_from_state(state),
        &run_plan_activation_from_state(state),
        &live_assignment_map(state),
        site_ids,
    )
    .map_err(|err| {
        protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &format!("failed to rebuild desired site plans for affected sites: {err}"),
        )
    })?;
    Ok(planned
        .iter()
        .map(|(site_id, site_plan)| (site_id.clone(), full_site_plan_record(site_id, site_plan)))
        .collect())
}

pub(super) fn load_site_manager_state(
    app: &ControlStateApp,
    site_id: &str,
) -> std::result::Result<SiteManagerStateView, ProtocolErrorResponse> {
    read_json(
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

pub(super) fn load_launched_site(
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

pub(super) fn load_site_controller_plan(
    app: &ControlStateApp,
    site_id: &str,
) -> std::result::Result<SiteControllerPlan, ProtocolErrorResponse> {
    if site_id == app.controller_plan.site_id {
        return Ok(app.controller_plan.as_ref().clone());
    }
    let path = site_controller_plan_path_for_site(app, site_id);
    read_json(&path, "site controller plan").map_err(|err| {
        protocol_error(
            ProtocolErrorCode::SiteNotActive,
            &format!("site `{site_id}` controller plan is unavailable: {err}"),
        )
    })
}

pub(super) fn load_site_runtime_plan(
    app: &ControlStateApp,
    site_id: &str,
) -> std::result::Result<SiteControllerRuntimePlan, ProtocolErrorResponse> {
    Ok(site_controller_runtime_plan_from_controller_plan(
        &load_site_controller_plan(app, site_id)?,
    ))
}

fn controller_authority_url<'a>(
    app: &'a ControlStateApp,
    site_id: &str,
) -> std::result::Result<&'a str, ProtocolErrorResponse> {
    if site_id == app.controller_plan.site_id {
        return Ok(app.controller_plan.authority_url.as_str());
    }
    app.peer_controllers
        .get(site_id)
        .map(|controller| controller.authority_url.as_str())
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::SiteNotActive,
                &format!("site `{site_id}` controller metadata is unavailable"),
            )
        })
}

pub(super) fn load_site_runtime_plan_at(
    site_state_root: &Path,
) -> std::result::Result<SiteControllerRuntimePlan, ProtocolErrorResponse> {
    let plan: SiteControllerPlan = read_json(
        &site_controller_plan_path(site_state_root),
        "site controller plan",
    )
    .map_err(|err| {
        protocol_error(
            ProtocolErrorCode::SiteNotActive,
            &format!(
                "site controller plan under `{}` is unavailable: {err}",
                site_state_root.display()
            ),
        )
    })?;
    Ok(site_controller_runtime_plan_from_controller_plan(&plan))
}

pub(super) fn load_site_manager_state_at(
    site_state_root: &Path,
) -> std::result::Result<SiteManagerStateView, ProtocolErrorResponse> {
    read_json(
        &site_state_root.join("manager-state.json"),
        "site manager state",
    )
    .map_err(|err| {
        protocol_error(
            ProtocolErrorCode::SiteNotActive,
            &format!(
                "site manager state under `{}` is unavailable: {err}",
                site_state_root.display()
            ),
        )
    })
}

pub(super) async fn publish_dynamic_capability_origin(
    app: &ControlStateApp,
    site_id: &str,
    request: &dynamic_caps::PublishDynamicCapabilityOriginRequest,
) -> std::result::Result<dynamic_caps::PublishDynamicCapabilityOriginResponse, ProtocolErrorResponse>
{
    let url = format!(
        "{}/v1/internal/dynamic-caps/origins/publish",
        controller_authority_url(app, site_id)?.trim_end_matches('/')
    );
    let response = app
        .client
        .post(url)
        .header(FRAMEWORK_AUTH_HEADER, app.control_state_auth_token.as_ref())
        .json(request)
        .send()
        .await
        .map_err(|err| {
            protocol_error(
                ProtocolErrorCode::OriginUnavailable,
                &format!(
                    "failed to reach site controller on site `{site_id}` while publishing dynamic \
                     capability origin: {err}"
                ),
            )
        })?;
    if response.status().is_success() {
        return response.json().await.map_err(|err| {
            protocol_error(
                ProtocolErrorCode::OriginUnavailable,
                &format!(
                    "site controller on site `{site_id}` returned invalid JSON while publishing \
                     dynamic capability origin: {err}"
                ),
            )
        });
    }
    let status = response.status();
    let body = response.bytes().await.map_err(|err| {
        protocol_error(
            ProtocolErrorCode::OriginUnavailable,
            &format!(
                "failed to read site controller error response on site `{site_id}` while \
                 publishing dynamic capability origin: {err}"
            ),
        )
    })?;
    if let Ok(protocol_error) = serde_json::from_slice::<ProtocolErrorResponse>(&body) {
        return Err(protocol_error);
    }
    Err(protocol_error(
        ProtocolErrorCode::OriginUnavailable,
        &format!(
            "site controller on site `{site_id}` returned {status} while publishing dynamic \
             capability origin"
        ),
    ))
}

#[derive(Clone, Debug)]
pub(super) struct DynamicCapabilityRuntimeEndpoint {
    pub(super) site_id: String,
    pub(super) runtime: LiveComponentRuntimeMetadata,
}

pub(super) fn dynamic_capability_component_runtime_endpoint(
    app: &ControlStateApp,
    state: &FrameworkControlState,
    logical_component_id: &str,
) -> std::result::Result<DynamicCapabilityRuntimeEndpoint, ProtocolErrorResponse> {
    let moniker = dynamic_caps::moniker_from_logical_component_id(logical_component_id)?;
    let assignments = live_assignment_map(state);
    let site_id = assignments.get(moniker).ok_or_else(|| {
        protocol_error(
            ProtocolErrorCode::OriginUnavailable,
            &format!("live component `{logical_component_id}` is not assigned to a live site"),
        )
    })?;
    let site_plan = load_site_runtime_plan(app, site_id)?;
    let runtime = app
        .runtime
        .collect_live_component_runtime_metadata(&site_plan)
        .map_err(|err| {
            protocol_error(
                ProtocolErrorCode::OriginUnavailable,
                &format!(
                    "failed to resolve live runtime metadata for component \
                     `{logical_component_id}` on site `{site_id}`: {err}"
                ),
            )
        })?
        .remove(moniker)
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::OriginUnavailable,
                &format!(
                    "live runtime metadata for component `{logical_component_id}` is unavailable \
                     on site `{site_id}`"
                ),
            )
        })?;
    Ok(DynamicCapabilityRuntimeEndpoint {
        site_id: site_id.clone(),
        runtime,
    })
}

pub(super) fn dynamic_capability_origin_route_surface(
    runtime: &LiveComponentRuntimeMetadata,
    site_components: &BTreeMap<String, LiveComponentRuntimeMetadata>,
    site_router: &MeshConfigPublic,
    site_kind: SiteKind,
    route_id: &str,
    root_authority_selector: &RootAuthoritySelectorIr,
    allowed_issuers: Vec<String>,
) -> std::result::Result<(InboundRoute, String, MeshProtocol), ProtocolErrorResponse> {
    match root_authority_selector {
        RootAuthoritySelectorIr::SelfProvide { provide_name, .. } => {
            let static_route = runtime
                .mesh_config
                .inbound
                .iter()
                .find(|route| {
                    route.capability == *provide_name
                        && matches!(route.target, InboundTarget::Local { .. })
                })
                .ok_or_else(|| {
                    protocol_error(
                        ProtocolErrorCode::OriginUnavailable,
                        &format!(
                            "live self-provide origin route `{}` is unavailable for component `{}`",
                            provide_name, runtime.moniker
                        ),
                    )
                })?;
            let route = InboundRoute {
                route_id: route_id.to_string(),
                capability: static_route.capability.clone(),
                capability_kind: static_route.capability_kind.clone(),
                capability_profile: static_route.capability_profile.clone(),
                protocol: static_route.protocol,
                http_plugins: static_route.http_plugins.clone(),
                target: InboundTarget::MeshForward {
                    peer_addr: runtime.host_mesh_addr.clone(),
                    peer_id: runtime.mesh_config.identity.id.clone(),
                    route_id: static_route.route_id.clone(),
                    capability: static_route.capability.clone(),
                },
                allowed_issuers,
            };
            Ok((
                route,
                static_route.capability.clone(),
                static_route.protocol,
            ))
        }
        RootAuthoritySelectorIr::Binding {
            slot_name,
            provider_capability_name,
            ..
        } => {
            let route = amber_mesh::dynamic_caps::exact_root_outbound_route(
                runtime.mesh_config.outbound.iter(),
                root_authority_selector,
            )
            .map_err(|err| match err {
                amber_mesh::dynamic_caps::ExactRootRouteError::InvalidLogicalComponentId => {
                    protocol_error(
                        ProtocolErrorCode::OriginUnavailable,
                        &format!(
                            "dynamic capability root selector is malformed for component `{}`",
                            runtime.moniker
                        ),
                    )
                }
                amber_mesh::dynamic_caps::ExactRootRouteError::NotFound => protocol_error(
                    ProtocolErrorCode::OriginUnavailable,
                    &format!(
                        "live slot origin `{slot_name}` backed by capability \
                         `{provider_capability_name}` is unavailable for component `{}`",
                        runtime.moniker
                    ),
                ),
                amber_mesh::dynamic_caps::ExactRootRouteError::Ambiguous => protocol_error(
                    ProtocolErrorCode::AuthorityPathUnavailable,
                    &format!(
                        "slot `{slot_name}` on component `{}` resolves to multiple outbound \
                         routes for capability `{provider_capability_name}`",
                        runtime.moniker
                    ),
                ),
            })?
            .expect("self-provide roots should be handled before outbound route resolution");
            let peer_addr =
                dynamic_capability_origin_mesh_peer_addr(site_components, site_kind, route);
            Ok((
                InboundRoute {
                    route_id: route_id.to_string(),
                    capability: route.capability.clone(),
                    capability_kind: route.capability_kind.clone(),
                    capability_profile: route.capability_profile.clone(),
                    protocol: route.protocol,
                    http_plugins: Vec::new(),
                    target: InboundTarget::MeshForward {
                        peer_addr,
                        peer_id: route.peer_id.clone(),
                        route_id: route.route_id.clone(),
                        capability: route.capability.clone(),
                    },
                    allowed_issuers,
                },
                route.capability.clone(),
                route.protocol,
            ))
        }
        RootAuthoritySelectorIr::ExternalSlotBinding {
            external_slot_name, ..
        } => {
            let static_route_id = router_external_route_id(external_slot_name);
            let static_route = site_router
                .inbound
                .iter()
                .find(|route| {
                    route.route_id == static_route_id
                        && route.capability == *external_slot_name
                        && matches!(route.target, InboundTarget::External { .. })
                })
                .ok_or_else(|| {
                    protocol_error(
                        ProtocolErrorCode::OriginUnavailable,
                        &format!(
                            "live external slot origin `{external_slot_name}` is unavailable for \
                             component `{}`",
                            runtime.moniker
                        ),
                    )
                })?;
            let mut route = static_route.clone();
            route.allowed_issuers = allowed_issuers;
            Ok((
                route,
                static_route.capability.clone(),
                static_route.protocol,
            ))
        }
    }
}

fn dynamic_capability_origin_mesh_peer_addr(
    site_components: &BTreeMap<String, LiveComponentRuntimeMetadata>,
    site_kind: SiteKind,
    route: &OutboundRoute,
) -> String {
    if let Some(peer_runtime) = site_components
        .values()
        .find(|component| component.mesh_config.identity.id == route.peer_id)
    {
        return peer_runtime.host_mesh_addr.clone();
    }
    if matches!(site_kind, SiteKind::Direct | SiteKind::Vm) {
        #[cfg(target_os = "linux")]
        if let Ok(addr) = route.peer_addr.parse::<SocketAddr>()
            && addr.ip() == Ipv4Addr::new(10, 0, 2, 2)
        {
            return SocketAddr::from((Ipv4Addr::LOCALHOST, addr.port())).to_string();
        }
    }
    route.peer_addr.clone()
}

pub(super) fn dynamic_capability_origin_target_mesh_peer(
    runtime: &LiveComponentRuntimeMetadata,
    site_components: &BTreeMap<String, LiveComponentRuntimeMetadata>,
    route: &InboundRoute,
) -> std::result::Result<Option<MeshPeer>, ProtocolErrorResponse> {
    let InboundTarget::MeshForward { peer_id, .. } = &route.target else {
        return Ok(None);
    };
    if peer_id == &runtime.mesh_config.identity.id {
        return Ok(Some(MeshPeer {
            id: runtime.mesh_config.identity.id.clone(),
            public_key: runtime.mesh_config.identity.public_key,
        }));
    }
    if let Some(peer) = runtime
        .mesh_config
        .peers
        .iter()
        .find(|peer| peer.id == *peer_id)
    {
        return Ok(Some(peer.clone()));
    }
    if let Some(peer_runtime) = site_components
        .values()
        .find(|component| component.mesh_config.identity.id == *peer_id)
    {
        return Ok(Some(MeshPeer {
            id: peer_runtime.mesh_config.identity.id.clone(),
            public_key: peer_runtime.mesh_config.identity.public_key,
        }));
    }
    Err(protocol_error(
        ProtocolErrorCode::OriginUnavailable,
        &format!("dynamic capability origin target peer `{peer_id}` is unavailable"),
    ))
}

fn push_unique_mesh_peer(peers: &mut Vec<MeshPeer>, peer: MeshPeer) {
    if peers.iter().all(|existing| existing.id != peer.id) {
        peers.push(peer);
    }
}

pub(super) fn dynamic_capability_allowed_mesh_peers(
    allowed_peers: &[dynamic_caps::DynamicCapabilityAllowedPeer],
) -> std::result::Result<Vec<MeshPeer>, ProtocolErrorResponse> {
    allowed_peers
        .iter()
        .map(|peer| {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(peer.peer_key_b64.as_bytes())
                .map_err(|err| {
                    protocol_error(
                        ProtocolErrorCode::PathEstablishmentFailed,
                        &format!("dynamic capability peer key is invalid: {err}"),
                    )
                })?;
            let public_key: [u8; 32] = decoded.as_slice().try_into().map_err(|_| {
                protocol_error(
                    ProtocolErrorCode::PathEstablishmentFailed,
                    "dynamic capability peer key must be exactly 32 bytes",
                )
            })?;
            Ok(MeshPeer {
                id: peer.peer_id.clone(),
                public_key,
            })
        })
        .collect()
}

pub(super) async fn publish_dynamic_capability_origin_local(
    app: &LocalDynamicCapabilityOriginApp,
    request: dynamic_caps::PublishDynamicCapabilityOriginRequest,
) -> std::result::Result<dynamic_caps::PublishDynamicCapabilityOriginResponse, ProtocolApiError> {
    let site_plan = load_site_runtime_plan_at(&app.site_state_root)?;
    let holder_component_id = match &request.root_authority_selector {
        RootAuthoritySelectorIr::SelfProvide { component_id, .. } => component_id.clone(),
        RootAuthoritySelectorIr::Binding {
            consumer_component_id,
            ..
        }
        | RootAuthoritySelectorIr::ExternalSlotBinding {
            consumer_component_id,
            ..
        } => consumer_component_id.clone(),
    };
    let holder_moniker = dynamic_caps::moniker_from_logical_component_id(&holder_component_id)?;
    let mut site_components = app
        .runtime
        .collect_live_component_runtime_metadata(&site_plan)
        .map_err(|err| {
            protocol_error(
                ProtocolErrorCode::OriginUnavailable,
                &format!(
                    "failed to collect live runtime metadata on site `{}`: {err}",
                    site_plan.site_id
                ),
            )
        })?;
    let site_router = app
        .runtime
        .load_live_site_router_mesh_config(&site_plan)
        .map_err(|err| {
            protocol_error(
                ProtocolErrorCode::OriginUnavailable,
                &format!(
                    "failed to collect live router metadata on site `{}`: {err}",
                    site_plan.site_id
                ),
            )
        })?;
    let runtime = site_components.remove(holder_moniker).ok_or_else(|| {
        protocol_error(
            ProtocolErrorCode::OriginUnavailable,
            &format!(
                "live runtime metadata for root holder `{holder_component_id}` is unavailable on \
                 site `{}`",
                site_plan.site_id
            ),
        )
    })?;
    let manager_state = load_site_manager_state_at(&app.site_state_root)?;
    let router_control = manager_state.router_control.ok_or_else(|| {
        protocol_error(
            ProtocolErrorCode::OriginUnavailable,
            &format!(
                "site `{}` router control endpoint is unavailable",
                site_plan.site_id
            ),
        )
    })?;
    let endpoint = parse_control_endpoint(&router_control).map_err(|err| {
        protocol_error(
            ProtocolErrorCode::OriginUnavailable,
            &format!(
                "site `{}` router control endpoint is invalid: {err}",
                site_plan.site_id
            ),
        )
    })?;
    let allowed_issuers = request
        .allowed_peers
        .iter()
        .map(|peer| peer.peer_id.clone())
        .collect::<Vec<_>>();
    let (route, capability, protocol) = dynamic_capability_origin_route_surface(
        &runtime,
        &site_components,
        &site_router,
        site_plan.kind,
        &request.route_id,
        &request.root_authority_selector,
        allowed_issuers,
    )?;
    let published_route_id = route.route_id.clone();
    let mut peers = dynamic_capability_allowed_mesh_peers(&request.allowed_peers)?;
    if let Some(target_peer) =
        dynamic_capability_origin_target_mesh_peer(&runtime, &site_components, &route)?
    {
        push_unique_mesh_peer(&mut peers, target_peer);
    }
    apply_route_overlay_with_retry(
        &endpoint,
        &request.overlay_id,
        &peers,
        &[route],
        Duration::from_secs(30),
    )
    .await
    .map_err(|err| {
        ProtocolApiError::from(protocol_error(
            ProtocolErrorCode::PathEstablishmentFailed,
            &format!(
                "failed to publish dynamic capability origin overlay `{}` on site `{}`: {err}",
                request.overlay_id, site_plan.site_id
            ),
        ))
    })?;
    Ok(dynamic_caps::PublishDynamicCapabilityOriginResponse {
        route_id: published_route_id,
        capability,
        protocol: match protocol {
            MeshProtocol::Http => "http",
            MeshProtocol::Tcp => "tcp",
        }
        .to_string(),
    })
}

pub(super) async fn call_site_controller<B: Serialize>(
    app: &ControlStateApp,
    site_id: &str,
    path: &str,
    body: Option<&B>,
    error_code: ProtocolErrorCode,
    action: &str,
) -> std::result::Result<(), ProtocolErrorResponse> {
    if site_id == app.controller_plan.site_id {
        let local_child_id = || -> std::result::Result<u64, ProtocolErrorResponse> {
            path.rsplit('/')
                .nth(1)
                .ok_or_else(|| {
                    controller_protocol_error(
                        error_code,
                        site_id,
                        action,
                        format!("site controller path `{path}` is malformed"),
                    )
                })?
                .parse()
                .map_err(|err| {
                    controller_protocol_error(
                        error_code,
                        site_id,
                        action,
                        format!("site controller child id in `{path}` is malformed: {err}"),
                    )
                })
        };
        match path {
            path if path.ends_with("/prepare") => {
                let request = serde_json::to_value(body).expect("site op body should serialize");
                let request = serde_json::from_value::<SiteControllerPrepareRequest>(request)
                    .expect("prepare request should deserialize");
                return app
                    .runtime
                    .prepare_child(&app.controller_plan, local_child_id()?, request.site_plan)
                    .await
                    .map_err(|err| controller_protocol_error(error_code, site_id, action, err));
            }
            path if path.ends_with("/publish") => {
                let request = serde_json::to_value(body).expect("site op body should serialize");
                let request = serde_json::from_value::<SiteControllerPublishRequest>(request)
                    .expect("publish request should deserialize");
                return app
                    .runtime
                    .publish_child(&app.controller_plan, local_child_id()?, request.site_plan)
                    .await
                    .map_err(|err| controller_protocol_error(error_code, site_id, action, err));
            }
            path if path.ends_with("/destroy") => {
                let request = serde_json::to_value(body).expect("site op body should serialize");
                let request = serde_json::from_value::<SiteControllerDestroyRequest>(request)
                    .expect("destroy request should deserialize");
                return app
                    .runtime
                    .destroy_child(
                        &app.controller_plan,
                        local_child_id()?,
                        request.desired_site_plan,
                    )
                    .await
                    .map_err(|err| controller_protocol_error(error_code, site_id, action, err));
            }
            _ => {}
        }
    } else {
        let controller = app.peer_controllers.get(site_id).ok_or_else(|| {
            controller_protocol_error(
                error_code,
                site_id,
                action,
                "site controller is not present in peer metadata",
            )
        })?;
        let url = format!("{}{}", controller.authority_url.trim_end_matches('/'), path);
        let request = app
            .client
            .post(url)
            .header(FRAMEWORK_AUTH_HEADER, app.control_state_auth_token.as_ref());
        let request = if let Some(body) = body {
            request.json(body)
        } else {
            request
        };
        let response = request
            .send()
            .await
            .map_err(|err| controller_protocol_error(error_code, site_id, action, err))?;
        if response.status().is_success() {
            return Ok(());
        }
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(controller_protocol_error(
            error_code,
            site_id,
            action,
            format!("HTTP {status}: {}", body.trim()),
        ));
    }
    Err(controller_protocol_error(
        error_code,
        site_id,
        action,
        format!("unsupported site controller action path `{path}`"),
    ))
}

pub(super) async fn prepare_child_on_site(
    app: &ControlStateApp,
    child_id: u64,
    site_plan: &DynamicSitePlanRecord,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let path = format!("/v1/controller/site/children/{child_id}/prepare");
    call_site_controller(
        app,
        &site_plan.site_id,
        &path,
        Some(&SiteControllerPrepareRequest {
            site_plan: site_plan.clone(),
        }),
        ProtocolErrorCode::PrepareFailed,
        "prepare child",
    )
    .await
}

pub(super) async fn publish_child_on_site(
    app: &ControlStateApp,
    child_id: u64,
    site_plan: &DynamicSitePlanRecord,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let path = format!("/v1/controller/site/children/{child_id}/publish");
    call_site_controller(
        app,
        &site_plan.site_id,
        &path,
        Some(&SiteControllerPublishRequest {
            site_plan: site_plan.clone(),
        }),
        ProtocolErrorCode::PublishFailed,
        "publish child",
    )
    .await
}

fn site_controller_child_needs_prepare(err: &ProtocolErrorResponse, child_id: u64) -> bool {
    err.code == ProtocolErrorCode::PublishFailed
        && err
            .message
            .contains(&format!("site controller child {child_id} is not prepared"))
}

pub(super) async fn publish_child_on_site_with_prepare_retry(
    app: &ControlStateApp,
    child_id: u64,
    site_plan: &DynamicSitePlanRecord,
) -> std::result::Result<(), ProtocolErrorResponse> {
    match publish_child_on_site(app, child_id, site_plan).await {
        Ok(()) => Ok(()),
        Err(err) if site_controller_child_needs_prepare(&err, child_id) => {
            prepare_child_on_site(app, child_id, site_plan).await?;
            publish_child_on_site(app, child_id, site_plan).await
        }
        Err(err) => Err(err),
    }
}

pub(super) async fn rollback_child_on_site(
    app: &ControlStateApp,
    child_id: u64,
    site_id: &str,
) -> Result<()> {
    if site_id == app.controller_plan.site_id {
        return app
            .runtime
            .rollback_child(&app.controller_plan, child_id)
            .await;
    }
    let path = format!("/v1/controller/site/children/{child_id}/rollback");
    let controller = app
        .peer_controllers
        .get(site_id)
        .ok_or_else(|| miette::miette!("site `{site_id}` controller metadata is unavailable"))?;
    let response = app
        .client
        .post(format!(
            "{}{}",
            controller.authority_url.trim_end_matches('/'),
            path
        ))
        .header(FRAMEWORK_AUTH_HEADER, app.control_state_auth_token.as_ref())
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

pub(super) async fn destroy_child_on_site(
    app: &ControlStateApp,
    child_id: u64,
    site_id: &str,
    desired_site_plan: Option<DynamicSitePlanRecord>,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let path = format!("/v1/controller/site/children/{child_id}/destroy");
    call_site_controller(
        app,
        site_id,
        &path,
        Some(&SiteControllerDestroyRequest { desired_site_plan }),
        ProtocolErrorCode::ControlStateUnavailable,
        "destroy child",
    )
    .await
}

pub(super) async fn publish_external_slot_overlay(
    app: &ControlStateApp,
    child: &LiveChildRecord,
    link: &RunLink,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let overlay_id = overlay_id_for_link_action(child, link, |action| {
        matches!(action, DynamicOverlayAction::ExternalSlot { .. })
    })?;
    let provider = load_launched_site(app, &link.provider_site)?;
    let consumer = load_launched_site(app, &link.consumer_site)?;
    let provider_output_dir =
        provider_output_dir_for_link(app, child, Path::new(&provider.receipt.artifact_dir), link);
    let external_url = app
        .runtime
        .resolve_link_external_url(
            &provider,
            &provider_output_dir,
            link,
            consumer.receipt.kind,
            &app.run_root,
        )
        .await
        .map_err(|err| {
            controller_protocol_error(
                ProtocolErrorCode::PublishFailed,
                &link.consumer_site,
                "compute external slot overlay",
                err,
            )
        })?;
    register_external_slot_with_retry(
        &consumer.router_control,
        &link.external_slot_name,
        &external_url,
        Duration::from_secs(30),
    )
    .await
    .map_err(|err| {
        controller_protocol_error(
            ProtocolErrorCode::PublishFailed,
            &link.consumer_site,
            "publish external slot overlay",
            err,
        )
    })?;
    app.runtime
        .update_desired_overlay_for_consumer(
            &site_state_root_for(app, &link.consumer_site),
            overlay_id,
            DesiredExternalSlotOverlay {
                slot_name: link.external_slot_name.clone(),
                url: external_url,
            },
        )
        .map_err(|err| {
            controller_protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &link.consumer_site,
                "persist desired external slot overlay",
                err,
            )
        })
}

pub(super) async fn publish_export_peer_overlay(
    app: &ControlStateApp,
    child: &LiveChildRecord,
    link: &RunLink,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let overlay_id = overlay_id_for_link_action(child, link, |action| {
        matches!(action, DynamicOverlayAction::ExportPeer { .. })
    })?;
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
        controller_protocol_error(
            ProtocolErrorCode::PublishFailed,
            &link.provider_site,
            "publish export-peer overlay",
            err,
        )
    })?;
    app.runtime
        .update_desired_overlay_for_provider(
            &site_state_root_for(app, &link.provider_site),
            overlay_id,
            DesiredExportPeerOverlay {
                export_name: link.export_name.clone(),
                peer_id: consumer.router_identity.id,
                peer_key_b64: consumer_key,
                protocol: link.protocol.to_string(),
                route_id: Some(route_id),
            },
        )
        .map_err(|err| {
            controller_protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &link.provider_site,
                "persist desired export-peer overlay",
                err,
            )
        })
}

pub(super) fn child_link_records(child: &LiveChildRecord) -> Vec<RunLink> {
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

pub(super) fn child_link_overlays_are_active(child: &LiveChildRecord) -> bool {
    matches!(
        child.state,
        ChildState::CreateCommittedHidden
            | ChildState::Live
            | ChildState::DestroyRequested
            | ChildState::DestroyRetracted
    )
}

pub(super) fn link_still_required(
    state: &FrameworkControlState,
    removed_child_id: u64,
    link: &RunLink,
) -> bool {
    visible_child_records(state)
        .filter(|candidate| candidate.child_id != removed_child_id)
        .filter(|candidate| child_link_overlays_are_active(candidate))
        .any(|candidate| {
            child_link_records(candidate)
                .iter()
                .any(|candidate_link| candidate_link == link)
        })
}

pub(super) fn provider_output_dir_for_link(
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
    site_controller_runtime_child_root_for_site(
        &site_state_root_for(app, &link.provider_site),
        child.child_id,
    )
    .join("artifact")
}

pub(super) fn export_peer_route_id(
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

pub(super) fn overlay_id_for_link_action<'a>(
    child: &'a LiveChildRecord,
    link: &RunLink,
    match_action: impl Fn(&DynamicOverlayAction) -> bool,
) -> std::result::Result<&'a str, ProtocolErrorResponse> {
    child
        .overlays
        .iter()
        .find(|overlay| match &overlay.action {
            DynamicOverlayAction::ExternalSlot { link: overlay_link }
            | DynamicOverlayAction::ExportPeer { link: overlay_link } => {
                overlay_link == link && match_action(&overlay.action)
            }
        })
        .map(|overlay| overlay.overlay_id.as_str())
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                "authoritative child overlay metadata is incomplete",
            )
        })
}

pub(super) fn link_mesh_protocol(protocol: NetworkProtocol) -> Result<MeshProtocol> {
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

pub(super) async fn publish_link_overlays(
    app: &ControlStateApp,
    child: &LiveChildRecord,
    link: &RunLink,
) -> std::result::Result<(), ProtocolErrorResponse> {
    publish_external_slot_overlay(app, child, link).await?;
    publish_export_peer_overlay(app, child, link).await
}

pub(super) async fn retract_link_overlays(
    app: &ControlStateApp,
    child: &LiveChildRecord,
    link: &RunLink,
) -> std::result::Result<(), ProtocolErrorResponse> {
    clear_external_slot_overlay(app, child.child_id, child, link).await?;
    clear_export_peer_overlay(app, child.child_id, child, link).await
}

pub(super) async fn clear_external_slot_overlay(
    app: &ControlStateApp,
    child_id: u64,
    child: &LiveChildRecord,
    link: &RunLink,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let overlay_id = overlay_id_for_link_action(child, link, |action| {
        matches!(action, DynamicOverlayAction::ExternalSlot { .. })
    })?;
    app.runtime
        .clear_desired_overlay_for_consumer(
            &site_state_root_for(app, &link.consumer_site),
            overlay_id,
        )
        .map_err(|err| {
            controller_protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &link.consumer_site,
                "persist external slot overlay removal",
                err,
            )
        })?;
    {
        let state = app.control_state.lock().await;
        if link_still_required(&state, child_id, link) {
            return Ok(());
        }
    }
    let consumer = load_launched_site(app, &link.consumer_site)?;
    clear_external_slot_with_retry(
        &consumer.router_control,
        &link.external_slot_name,
        Duration::from_secs(30),
    )
    .await
    .map_err(|err| {
        controller_protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &link.consumer_site,
            "retract external slot overlay",
            err,
        )
    })
}

pub(super) async fn clear_export_peer_overlay(
    app: &ControlStateApp,
    child_id: u64,
    child: &LiveChildRecord,
    link: &RunLink,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let overlay_id = overlay_id_for_link_action(child, link, |action| {
        matches!(action, DynamicOverlayAction::ExportPeer { .. })
    })?;
    app.runtime
        .clear_desired_overlay_for_provider(
            &site_state_root_for(app, &link.provider_site),
            overlay_id,
        )
        .map_err(|err| {
            controller_protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &link.provider_site,
                "persist export-peer overlay removal",
                err,
            )
        })?;
    {
        let state = app.control_state.lock().await;
        if link_still_required(&state, child_id, link) {
            return Ok(());
        }
    }
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
        controller_protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &link.provider_site,
            "retract export-peer overlay",
            err,
        )
    })
}

pub(super) async fn publish_child_overlays(
    app: &ControlStateApp,
    child: &LiveChildRecord,
) -> std::result::Result<(), ProtocolErrorResponse> {
    for link in child_link_records(child) {
        publish_link_overlays(app, child, &link).await?;
    }
    Ok(())
}

pub(super) async fn retract_child_overlays(
    app: &ControlStateApp,
    child: &LiveChildRecord,
) -> std::result::Result<(), ProtocolErrorResponse> {
    for link in child_link_records(child) {
        retract_link_overlays(app, child, &link).await?;
    }
    Ok(())
}

pub(super) async fn retract_dynamic_capability_origin_overlays(
    app: &ControlStateApp,
    child: &LiveChildRecord,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let overlays_by_site = {
        let state = app.control_state.lock().await;
        let Some(fragment) = child.fragment.as_ref() else {
            return Ok(());
        };
        let mut overlays_by_site = BTreeMap::<String, BTreeSet<String>>::new();
        for component in &fragment.components {
            if component.program.is_none() {
                continue;
            }
            let holder_component_id = dynamic_caps::logical_component_id(&component.moniker);
            for held in dynamic_caps::live_held_entries(&state, &holder_component_id)? {
                let selector = if let Some(selector) = held.root_authority_selector.clone() {
                    selector
                } else if let Some(grant_id) = held.grant_id.as_deref() {
                    state
                        .dynamic_capability_grants
                        .get(grant_id)
                        .ok_or_else(|| {
                            protocol_error(
                                ProtocolErrorCode::ControlStateUnavailable,
                                &format!("dynamic grant `{grant_id}` is missing from state"),
                            )
                        })?
                        .root_authority_selector
                        .clone()
                } else {
                    continue;
                };
                let site_id = site_id_for_root_authority_selector(&state, &selector)?;
                overlays_by_site.entry(site_id).or_default().insert(
                    dynamic_caps::origin_overlay_id(&holder_component_id, &selector),
                );
            }
        }
        overlays_by_site
    };

    for (site_id, overlay_ids) in overlays_by_site {
        let router_control = load_site_manager_state(app, &site_id)?
            .router_control
            .ok_or_else(|| {
                controller_protocol_error(
                    ProtocolErrorCode::ControlStateUnavailable,
                    &site_id,
                    "retract dynamic capability origin overlays",
                    "site router control endpoint is unavailable",
                )
            })?;
        let endpoint = parse_control_endpoint(&router_control).map_err(|err| {
            controller_protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &site_id,
                "retract dynamic capability origin overlays",
                format!("site router control endpoint is invalid: {err}"),
            )
        })?;
        for overlay_id in overlay_ids {
            revoke_route_overlay_with_retry(&endpoint, &overlay_id, Duration::from_secs(30))
                .await
                .map_err(|err| {
                    controller_protocol_error(
                        ProtocolErrorCode::ControlStateUnavailable,
                        &site_id,
                        "retract dynamic capability origin overlays",
                        err,
                    )
                })?;
        }
    }

    Ok(())
}

pub(super) fn child_site_publish_waves(child: &LiveChildRecord) -> Vec<Vec<String>> {
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
        .collect::<BTreeSet<_>>();
    let mut waves = Vec::new();
    let mut scheduled = BTreeSet::new();
    while !ready.is_empty() {
        let wave = ready.iter().cloned().collect::<Vec<_>>();
        let mut next_ready = BTreeSet::new();
        for site_id in &wave {
            if !scheduled.insert(site_id.clone()) {
                continue;
            }
            for consumer in outgoing
                .get(site_id)
                .into_iter()
                .flat_map(|sites| sites.iter())
            {
                let deps = incoming
                    .get_mut(consumer)
                    .expect("consumer dependencies should be tracked");
                deps.remove(site_id);
                if deps.is_empty() {
                    next_ready.insert(consumer.clone());
                }
            }
        }
        waves.push(wave);
        ready = next_ready;
    }

    let remaining = site_ids
        .into_iter()
        .filter(|site_id| scheduled.insert(site_id.clone()))
        .collect::<Vec<_>>();
    if !remaining.is_empty() {
        waves.push(remaining);
    }
    waves
}

pub(super) fn cloned_child_record(
    state: &FrameworkControlState,
    child_id: u64,
) -> std::result::Result<LiveChildRecord, ProtocolErrorResponse> {
    all_child_records(state)
        .find(|child| child.child_id == child_id)
        .cloned()
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &format!("child id {child_id} is missing from authoritative state"),
            )
        })
}

pub(super) async fn rollback_prepared_sites(
    app: &ControlStateApp,
    child_id: u64,
    prepared_sites: &[String],
) -> Result<()> {
    for site_id in prepared_sites {
        rollback_child_on_site(app, child_id, site_id).await?;
    }
    Ok(())
}

pub(super) async fn acquire_authority_lock(
    app: &ControlStateApp,
    authority_realm_id: usize,
) -> tokio::sync::OwnedMutexGuard<()> {
    let lock = {
        let mut locks = app.authority_locks.lock().await;
        locks
            .entry(authority_realm_id)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    };
    lock.lock_owned().await
}

pub(super) async fn continue_create_committed_hidden(
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
        .map(|site_plan| (site_plan.site_id.clone(), site_plan.clone()))
        .collect::<BTreeMap<_, _>>();
    let child_sites = site_plans.keys().cloned().collect::<BTreeSet<_>>();
    let links = child_link_records(&child);
    let mut published_child_sites = BTreeSet::new();
    let mut published_links = Vec::new();
    for wave in child_site_publish_waves(&child) {
        for site_id in &wave {
            for link in links.iter().filter(|link| link.consumer_site == *site_id) {
                let provider_ready = !child_sites.contains(&link.provider_site)
                    || published_child_sites.contains(&link.provider_site);
                if provider_ready {
                    publish_link_overlays(app, &child, link).await?;
                    published_links.push(link.clone());
                }
            }
        }
        let mut publish_tasks = tokio::task::JoinSet::new();
        for site_id in &wave {
            let app = app.clone();
            let child_id = child.child_id;
            let site_plan = site_plans
                .get(site_id)
                .expect("site plan should exist for wave site")
                .clone();
            let site_id = site_id.clone();
            publish_tasks.spawn(async move {
                publish_child_on_site_with_prepare_retry(&app, child_id, &site_plan)
                    .await
                    .map(|_| site_id)
            });
        }
        let mut first_error = None;
        let mut published_wave_sites = Vec::new();
        while let Some(result) = publish_tasks.join_next().await {
            match result {
                Ok(Ok(site_id)) => published_wave_sites.push(site_id),
                Ok(Err(err)) if first_error.is_none() => first_error = Some(err),
                Ok(Err(_)) => {}
                Err(err) if first_error.is_none() => {
                    first_error = Some(protocol_error(
                        ProtocolErrorCode::PublishFailed,
                        &format!("site publish task failed: {err}"),
                    ));
                }
                Err(_) => {}
            }
        }
        if let Some(err) = first_error {
            let desired_site_plans = {
                let state = app.control_state.lock().await;
                desired_site_plan_map(&state, &child_sites)?
            };
            let mut cleanup_error = None;
            for link in published_links.iter().rev() {
                if let Err(retract_err) = retract_link_overlays(app, &child, link).await
                    && cleanup_error.is_none()
                {
                    cleanup_error = Some(retract_err);
                }
            }

            let mut destroy_tasks = tokio::task::JoinSet::new();
            for site_id in &child_sites {
                let app = app.clone();
                let desired_site_plan = desired_site_plans.get(site_id).cloned();
                let site_id = site_id.clone();
                destroy_tasks.spawn(async move {
                    destroy_child_on_site(&app, child.child_id, &site_id, desired_site_plan).await
                });
            }
            while let Some(result) = destroy_tasks.join_next().await {
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(destroy_err)) if cleanup_error.is_none() => {
                        cleanup_error = Some(destroy_err);
                    }
                    Ok(Err(_)) => {}
                    Err(join_err) if cleanup_error.is_none() => {
                        cleanup_error = Some(protocol_error(
                            ProtocolErrorCode::PublishFailed,
                            &format!("site destroy task failed: {join_err}"),
                        ));
                    }
                    Err(_) => {}
                }
            }

            if let Some(cleanup_error) = cleanup_error {
                return Err(protocol_error(
                    ProtocolErrorCode::PublishFailed,
                    &format!("{}; cleanup failed: {}", err.message, cleanup_error.message),
                ));
            }

            let mut state = app.control_state.lock().await;
            if child_record_location(&state, child.child_id).is_ok() {
                let tx_id = child_create_tx_id(&state, child.child_id)?;
                persist_control_state_update(
                    &mut state,
                    &app.state_path,
                    "create_aborted",
                    |state| {
                        append_journal_entry(state, tx_id, &child, ChildState::CreateAborted);
                        remove_child_record(state, child.child_id)?;
                        Ok(())
                    },
                )?;
            }
            return Err(err);
        }
        for site_id in published_wave_sites {
            published_child_sites.insert(site_id);
        }
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
    let tx_id = child_create_tx_id(&state, child_id)?;
    persist_control_state_update(&mut state, &app.state_path, "create_live", |state| {
        append_journal_entry(state, tx_id, &child, ChildState::Live);
        move_pending_create_to_live(state, child_id)?;
        Ok(())
    })
}

pub(super) async fn continue_destroy_retracted(
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
        desired_site_plan_map(
            &state,
            &child
                .site_plans
                .iter()
                .map(|site_plan| site_plan.site_id.clone())
                .collect(),
        )?
    };
    let mut destroy_tasks = tokio::task::JoinSet::new();
    for site_plan in child.site_plans.clone() {
        let app = app.clone();
        let desired_site_plan = desired_site_plans.get(&site_plan.site_id).cloned();
        destroy_tasks.spawn(async move {
            destroy_child_on_site(&app, child.child_id, &site_plan.site_id, desired_site_plan).await
        });
    }
    let mut first_error = None;
    while let Some(result) = destroy_tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(err)) if first_error.is_none() => first_error = Some(err),
            Ok(Err(_)) => {}
            Err(err) if first_error.is_none() => {
                first_error = Some(protocol_error(
                    ProtocolErrorCode::PublishFailed,
                    &format!("site destroy task failed: {err}"),
                ));
            }
            Err(_) => {}
        }
    }
    if let Some(err) = first_error {
        return Err(err);
    }

    let mut state = app.control_state.lock().await;
    let child = cloned_child_record(&state, child_id)?;
    if child.state != ChildState::DestroyRetracted {
        return Ok(());
    }
    let tx_id = child_destroy_tx_id(&state, child_id)?;
    persist_control_state_update(&mut state, &app.state_path, "destroy_committed", |state| {
        append_journal_entry(state, tx_id, &child, ChildState::DestroyCommitted);
        remove_pending_destroy(state, child_id)?;
        Ok(())
    })
}

pub(super) async fn continue_destroy_requested(
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
    retract_dynamic_capability_origin_overlays(app, &child).await?;

    {
        let mut state = app.control_state.lock().await;
        let child = cloned_child_record(&state, child_id)?;
        if child.state != ChildState::DestroyRequested {
            return Ok(());
        }
        let tx_id = child_destroy_tx_id(&state, child_id)?;
        persist_control_state_update(&mut state, &app.state_path, "destroy_retracted", |state| {
            remove_incident_bindings_from_survivors(state, child_id);
            transition_child_state(state, child_id, ChildState::DestroyRetracted)?;
            append_journal_entry(state, tx_id, &child, ChildState::DestroyRetracted);
            Ok(())
        })?;
    }

    continue_destroy_retracted(app, child_id).await
}

pub(super) async fn execute_create_child(
    app: &ControlStateApp,
    authority_realm_id: usize,
    request: CreateChildRequest,
) -> std::result::Result<CreateChildResponse, ProtocolApiError> {
    let _authority_guard = acquire_authority_lock(app, authority_realm_id).await;
    let child = {
        let mut state = app.control_state.lock().await;
        let child = prepare_child_record(&mut state, authority_realm_id, &request).await?;
        let tx_id = allocate_tx_id(&mut state);
        persist_control_state_update(&mut state, &app.state_path, "create_prepared", |state| {
            state.pending_creates.push(PendingCreateRecord {
                tx_id,
                child: child.clone(),
            });
            append_journal_entry(state, tx_id, &child, ChildState::CreateRequested);
            append_journal_entry(state, tx_id, &child, ChildState::CreatePrepared);
            Ok(())
        })?;
        (tx_id, child)
    };
    let (tx_id, child) = child;

    let mut prepared_sites = Vec::new();
    for site_plan in &child.site_plans {
        if let Err(err) = prepare_child_on_site(app, child.child_id, site_plan).await {
            let rollback_err = rollback_prepared_sites(app, child.child_id, &prepared_sites).await;
            let mut state = app.control_state.lock().await;
            if state
                .pending_creates
                .iter()
                .any(|candidate| candidate.child.child_id == child.child_id)
                && rollback_err.is_ok()
            {
                persist_control_state_update(
                    &mut state,
                    &app.state_path,
                    "create_aborted",
                    |state| {
                        append_journal_entry(state, tx_id, &child, ChildState::CreateAborted);
                        remove_pending_create(state, child.child_id)?;
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
                append_journal_entry(state, tx_id, &child, ChildState::CreateCommittedHidden);
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

pub(super) async fn execute_destroy_child(
    app: &ControlStateApp,
    authority_realm_id: usize,
    child_name: &str,
) -> std::result::Result<(), ProtocolApiError> {
    let _authority_guard = acquire_authority_lock(app, authority_realm_id).await;
    let next = {
        let mut state = app.control_state.lock().await;
        let Some(child) = state
            .live_children
            .iter()
            .chain(state.pending_destroys.iter().map(|record| &record.child))
            .find(|child| {
                child.authority_realm_id == authority_realm_id && child.name == child_name
            })
            .cloned()
        else {
            return Ok(());
        };
        match child.state {
            ChildState::Live => {
                let tx_id = allocate_tx_id(&mut state);
                persist_control_state_update(
                    &mut state,
                    &app.state_path,
                    "destroy_requested",
                    |state| {
                        append_journal_entry(state, tx_id, &child, ChildState::DestroyRequested);
                        move_live_child_to_pending_destroy(state, child.child_id, tx_id)?;
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

pub(super) async fn recover_control_state(app: &ControlStateApp) -> Result<()> {
    let children = {
        let state = app.control_state.lock().await;
        all_child_records(&state).cloned().collect::<Vec<_>>()
    };
    for child in children {
        match child.state {
            ChildState::CreateRequested => {
                let mut state = app.control_state.lock().await;
                if child_record_location(&state, child.child_id).is_ok() {
                    let tx_id = child_create_tx_id(&state, child.child_id)
                        .map_err(|err| miette::miette!(err.message))?;
                    persist_control_state_update(
                        &mut state,
                        &app.state_path,
                        "create_aborted",
                        |state| {
                            append_journal_entry(state, tx_id, &child, ChildState::CreateAborted);
                            remove_child_record(state, child.child_id)?;
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
                rollback_prepared_sites(app, child.child_id, &prepared_sites)
                    .await
                    .wrap_err_with(|| {
                        format!(
                            "failed to rollback prepared child `{}` during recovery",
                            child.name
                        )
                    })?;
                let mut state = app.control_state.lock().await;
                if child_record_location(&state, child.child_id).is_ok() {
                    let tx_id = child_create_tx_id(&state, child.child_id)
                        .map_err(|err| miette::miette!(err.message))?;
                    persist_control_state_update(
                        &mut state,
                        &app.state_path,
                        "create_aborted",
                        |state| {
                            append_journal_entry(state, tx_id, &child, ChildState::CreateAborted);
                            remove_child_record(state, child.child_id)?;
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
                // Live children have already completed publication. Replaying that publish step
                // on control-state startup can duplicate an already materialized child runtime.
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
