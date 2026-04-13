#[cfg(target_os = "linux")]
use std::net::Ipv4Addr;

use amber_mesh::{
    InboundRoute, InboundTarget, MeshConfigPublic, MeshPeer, OutboundRoute,
    router_external_route_id,
};
use amber_proxy::{ControlEndpoint, fetch_router_identity};

use super::{http::*, planner::*, state::*, *};

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ResolveExternalLinkUrlRequest {
    pub(crate) child_id: u64,
    pub(crate) link: RunLink,
    pub(crate) consumer_kind: SiteKind,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ResolveExternalLinkUrlResponse {
    pub(crate) external_url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PublishExternalSlotOverlayRequest {
    pub(crate) overlay_id: String,
    pub(crate) slot_name: String,
    pub(crate) url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ClearExternalSlotOverlayRequest {
    pub(crate) overlay_id: String,
    pub(crate) slot_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PublishExportPeerOverlayRequest {
    pub(crate) overlay_id: String,
    pub(crate) export_name: String,
    pub(crate) peer_id: String,
    pub(crate) peer_key_b64: String,
    pub(crate) protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) route_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ClearExportPeerOverlayRequest {
    pub(crate) overlay_id: String,
    pub(crate) export_name: String,
    pub(crate) peer_id: String,
    pub(crate) peer_key_b64: String,
    pub(crate) protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) route_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RevokeDynamicCapabilityOriginOverlaysRequest {
    pub(crate) overlay_ids: Vec<String>,
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

pub(super) fn load_site_manager_state(
    app: &ControlStateApp,
    site_id: &str,
) -> std::result::Result<SiteManagerStateView, ProtocolErrorResponse> {
    let state_path = site_state_path(&app.state_root, site_id);
    if state_path.is_file() {
        return read_json(&state_path, "site manager state").map_err(|err| {
            protocol_error(
                ProtocolErrorCode::SiteNotActive,
                &format!("site `{site_id}` manager state is unavailable: {err}"),
            )
        });
    }
    if site_id == app.controller_plan.site_id {
        return Ok(local_site_manager_state_view(app));
    }
    Err(protocol_error(
        ProtocolErrorCode::SiteNotActive,
        &format!(
            "site `{site_id}` manager state is unavailable: {}",
            state_path.display()
        ),
    ))
}

fn local_site_manager_state_view(app: &ControlStateApp) -> SiteManagerStateView {
    let runtime_plan = site_controller_runtime_plan_from_controller_plan(&app.controller_plan);
    let router_identity = app
        .runtime
        .load_live_site_router_mesh_config(&runtime_plan)
        .ok()
        .map(|router_mesh| {
            (
                router_mesh.identity.id,
                base64::engine::general_purpose::STANDARD.encode(router_mesh.identity.public_key),
            )
        });
    SiteManagerStateView {
        status: "running".to_string(),
        kind: app.controller_plan.kind,
        artifact_dir: app.controller_plan.artifact_dir.clone(),
        supervisor_pid: 0,
        process_pid: None,
        compose_project: app.controller_plan.compose_project.clone(),
        kubernetes_namespace: app.controller_plan.kubernetes_namespace.clone(),
        port_forward_pid: None,
        context: app.controller_plan.context.clone(),
        router_control: app.controller_plan.local_router_control.clone(),
        router_mesh_addr: app.controller_plan.published_router_mesh_addr.clone(),
        router_identity_id: router_identity.as_ref().map(|(id, _)| id.clone()),
        router_public_key_b64: router_identity.map(|(_, public_key_b64)| public_key_b64),
        site_controller_pid: None,
        site_controller_url: Some(app.controller_plan.authority_url.clone()),
    }
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

fn framework_route_overlay_id(authority_site_id: &str) -> String {
    format!("framework-component-routes:{authority_site_id}")
}

fn framework_component_route(
    record: &CapabilityInstanceRecord,
    allowed_issuers: Vec<String>,
    target: InboundTarget,
) -> InboundRoute {
    InboundRoute {
        route_id: record.route_id.clone(),
        capability: record.capability.clone(),
        capability_kind: Some("component".to_string()),
        capability_profile: None,
        protocol: MeshProtocol::Http,
        http_plugins: Vec::new(),
        target,
        allowed_issuers,
    }
}

fn framework_controller_external_target() -> InboundTarget {
    InboundTarget::External {
        url_env: amber_mesh::FRAMEWORK_COMPONENT_CONTROLLER_URL_ENV.to_string(),
        optional: false,
    }
}

async fn peer_router_identity_for_overlay(
    app: &ControlStateApp,
    site_id: &str,
) -> std::result::Result<MeshPeer, ProtocolErrorResponse> {
    if let Some(identity) = app.controller_plan.peer_router_identities.get(site_id) {
        return Ok(MeshPeer {
            id: identity.id.clone(),
            public_key: identity.public_key,
        });
    }
    let site_app = SiteControllerApp {
        control: app.clone(),
        router_auth_token: app.control_state_auth_token.clone(),
        ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let identity = loop {
        match super::site_controller::peer_router_identity_via_router(&site_app, site_id).await {
            Ok(identity) => break identity,
            Err(err)
                if err.0.code == ProtocolErrorCode::ControlStateUnavailable
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(err) => return Err(err.0),
        }
    };
    Ok(MeshPeer {
        id: identity.id,
        public_key: identity.public_key,
    })
}

fn peer_router_mesh_addr_for_overlay(
    app: &ControlStateApp,
    site_id: &str,
) -> std::result::Result<String, ProtocolErrorResponse> {
    app.controller_plan
        .peer_router_mesh_addrs
        .get(site_id)
        .cloned()
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &format!(
                    "site controller `{}` has no mesh address for peer site `{site_id}`",
                    app.controller_plan.site_id
                ),
            )
        })
}

fn local_router_control_endpoint(
    app: &ControlStateApp,
) -> std::result::Result<ControlEndpoint, ProtocolErrorResponse> {
    if let Some(raw) = app.controller_plan.local_router_control.as_deref() {
        return parse_control_endpoint(raw).map_err(|err| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &format!("local router control endpoint is invalid: {err}"),
            )
        });
    }
    let state = load_site_manager_state(app, &app.controller_plan.site_id)?;
    let raw = state.router_control.ok_or_else(|| {
        protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            "local router control endpoint is unavailable",
        )
    })?;
    parse_control_endpoint(&raw).map_err(|err| {
        protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &format!("local router control endpoint is invalid: {err}"),
        )
    })
}

pub(super) async fn local_router_identity_for_overlay(
    app: &ControlStateApp,
) -> std::result::Result<MeshPeer, ProtocolErrorResponse> {
    let state = load_site_manager_state(app, &app.controller_plan.site_id)?;
    if let (Some(id), Some(public_key_b64)) =
        (state.router_identity_id, state.router_public_key_b64)
        && let Ok(decoded) =
            base64::engine::general_purpose::STANDARD.decode(public_key_b64.as_bytes())
        && let Ok(public_key) = decoded.as_slice().try_into()
    {
        return Ok(MeshPeer { id, public_key });
    }
    if let Ok(router_mesh) = app.runtime.load_live_site_router_mesh_config(
        &site_controller_runtime_plan_from_controller_plan(&app.controller_plan),
    ) {
        return Ok(MeshPeer {
            id: router_mesh.identity.id,
            public_key: router_mesh.identity.public_key,
        });
    }
    let identity = fetch_router_identity(&local_router_control_endpoint(app)?)
        .await
        .map_err(|err| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &format!("failed to read local router identity: {err}"),
            )
        })?;
    Ok(MeshPeer {
        id: identity.id,
        public_key: identity.public_key,
    })
}

fn local_site_state_root(app: &ControlStateApp) -> &Path {
    Path::new(&app.controller_plan.site_state_root)
}

fn local_site_kind_from_state(
    state: &FrameworkControlState,
    site_id: &str,
) -> std::result::Result<SiteKind, ProtocolErrorResponse> {
    state
        .placement
        .offered_sites
        .get(site_id)
        .map(|site| site.kind)
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &format!("site `{site_id}` is missing from offered sites"),
            )
        })
}

pub(super) async fn resolve_external_link_url_local(
    app: &ControlStateApp,
    request: &ResolveExternalLinkUrlRequest,
) -> std::result::Result<ResolveExternalLinkUrlResponse, ProtocolErrorResponse> {
    if request.link.provider_site != app.controller_plan.site_id {
        return Err(controller_protocol_error(
            ProtocolErrorCode::PublishFailed,
            &request.link.provider_site,
            "resolve provider link url",
            format!(
                "controller `{}` only resolves provider surfaces for its own site",
                app.controller_plan.site_id
            ),
        ));
    }
    let child = {
        let state = app.control_state.lock().await;
        cloned_child_record(&state, request.child_id)?
    };
    let provider = load_launched_site(app, &app.controller_plan.site_id)?;
    let provider_output_dir = provider_output_dir_for_link(
        app,
        &child,
        Path::new(&provider.receipt.artifact_dir),
        &request.link,
    );
    let external_url = app
        .runtime
        .resolve_link_external_url(
            &provider,
            &provider_output_dir,
            &request.link,
            request.consumer_kind,
            &app.run_root,
        )
        .await
        .map_err(|err| {
            controller_protocol_error(
                ProtocolErrorCode::PublishFailed,
                &request.link.provider_site,
                "compute external slot overlay",
                err,
            )
        })?;
    Ok(ResolveExternalLinkUrlResponse { external_url })
}

pub(super) async fn publish_external_slot_overlay_local(
    app: &ControlStateApp,
    request: &PublishExternalSlotOverlayRequest,
) -> std::result::Result<(), ProtocolErrorResponse> {
    register_external_slot_with_retry(
        &local_router_control_endpoint(app)?,
        &request.slot_name,
        &request.url,
        Duration::from_secs(30),
    )
    .await
    .map_err(|err| {
        controller_protocol_error(
            ProtocolErrorCode::PublishFailed,
            &app.controller_plan.site_id,
            "publish external slot overlay",
            err,
        )
    })?;
    app.runtime
        .update_desired_overlay_for_consumer(
            local_site_state_root(app),
            &request.overlay_id,
            DesiredExternalSlotOverlay {
                slot_name: request.slot_name.clone(),
                url: request.url.clone(),
            },
        )
        .map_err(|err| {
            controller_protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &app.controller_plan.site_id,
                "persist desired external slot overlay",
                err,
            )
        })
}

pub(super) async fn clear_external_slot_overlay_local(
    app: &ControlStateApp,
    request: &ClearExternalSlotOverlayRequest,
) -> std::result::Result<(), ProtocolErrorResponse> {
    app.runtime
        .clear_desired_overlay_for_consumer(local_site_state_root(app), &request.overlay_id)
        .map_err(|err| {
            controller_protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &app.controller_plan.site_id,
                "persist external slot overlay removal",
                err,
            )
        })?;
    clear_external_slot_with_retry(
        &local_router_control_endpoint(app)?,
        &request.slot_name,
        Duration::from_secs(30),
    )
    .await
    .map_err(|err| {
        controller_protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &app.controller_plan.site_id,
            "retract external slot overlay",
            err,
        )
    })
}

pub(super) async fn publish_export_peer_overlay_local(
    app: &ControlStateApp,
    request: &PublishExportPeerOverlayRequest,
) -> std::result::Result<(), ProtocolErrorResponse> {
    register_export_peer_with_retry(
        &local_router_control_endpoint(app)?,
        &request.export_name,
        &request.peer_id,
        &request.peer_key_b64,
        &request.protocol,
        request.route_id.as_deref(),
        Duration::from_secs(30),
    )
    .await
    .map_err(|err| {
        controller_protocol_error(
            ProtocolErrorCode::PublishFailed,
            &app.controller_plan.site_id,
            "publish export-peer overlay",
            err,
        )
    })?;
    app.runtime
        .update_desired_overlay_for_provider(
            local_site_state_root(app),
            &request.overlay_id,
            DesiredExportPeerOverlay {
                export_name: request.export_name.clone(),
                peer_id: request.peer_id.clone(),
                peer_key_b64: request.peer_key_b64.clone(),
                protocol: request.protocol.clone(),
                route_id: request.route_id.clone(),
            },
        )
        .map_err(|err| {
            controller_protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &app.controller_plan.site_id,
                "persist desired export-peer overlay",
                err,
            )
        })
}

pub(super) async fn clear_export_peer_overlay_local(
    app: &ControlStateApp,
    request: &ClearExportPeerOverlayRequest,
) -> std::result::Result<(), ProtocolErrorResponse> {
    app.runtime
        .clear_desired_overlay_for_provider(local_site_state_root(app), &request.overlay_id)
        .map_err(|err| {
            controller_protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &app.controller_plan.site_id,
                "persist export-peer overlay removal",
                err,
            )
        })?;
    unregister_export_peer_with_retry(
        &local_router_control_endpoint(app)?,
        &request.export_name,
        &request.peer_id,
        &request.peer_key_b64,
        &request.protocol,
        request.route_id.as_deref(),
        Duration::from_secs(30),
    )
    .await
    .map_err(|err| {
        controller_protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &app.controller_plan.site_id,
            "retract export-peer overlay",
            err,
        )
    })
}

pub(super) async fn revoke_dynamic_capability_origin_overlays_local(
    app: &ControlStateApp,
    request: &RevokeDynamicCapabilityOriginOverlaysRequest,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let endpoint = local_router_control_endpoint(app)?;
    for overlay_id in &request.overlay_ids {
        revoke_route_overlay_with_retry(&endpoint, overlay_id, Duration::from_secs(30))
            .await
            .map_err(|err| {
                controller_protocol_error(
                    ProtocolErrorCode::ControlStateUnavailable,
                    &app.controller_plan.site_id,
                    "retract dynamic capability origin overlays",
                    err,
                )
            })?;
    }
    Ok(())
}

pub(super) async fn framework_route_overlay_payload(
    app: &ControlStateApp,
) -> std::result::Result<Option<DesiredRouteOverlay>, ProtocolErrorResponse> {
    let state = app.control_state.lock().await.clone();
    let local_site_id = app.controller_plan.site_id.clone();
    let mut overlay = DesiredRouteOverlay {
        peers: Vec::new(),
        inbound_routes: Vec::new(),
    };

    for record in state.capability_instances.values() {
        let authority_site_id = framework_authority_site_id(&state, record)?;
        let consumer_site_id = record.recipient_site_id.clone();

        if authority_site_id == local_site_id {
            if consumer_site_id == local_site_id {
                overlay.inbound_routes.push(framework_component_route(
                    record,
                    vec![record.recipient_peer_id.clone()],
                    framework_controller_external_target(),
                ));
                continue;
            }
            let consumer_peer = peer_router_identity_for_overlay(app, &consumer_site_id).await?;
            if !overlay.peers.iter().any(|peer| peer.id == consumer_peer.id) {
                overlay.peers.push(consumer_peer.clone());
            }
            overlay.inbound_routes.push(framework_component_route(
                record,
                vec![consumer_peer.id],
                framework_controller_external_target(),
            ));
            continue;
        }

        if consumer_site_id != local_site_id {
            continue;
        }

        let authority_peer = peer_router_identity_for_overlay(app, &authority_site_id).await?;
        let route = framework_component_route(
            record,
            vec![record.recipient_peer_id.clone()],
            InboundTarget::MeshForward {
                peer_addr: peer_router_mesh_addr_for_overlay(app, &authority_site_id)?,
                peer_id: authority_peer.id.clone(),
                route_id: record.route_id.clone(),
                capability: record.capability.clone(),
            },
        );
        if !overlay
            .peers
            .iter()
            .any(|peer| peer.id == authority_peer.id)
        {
            overlay.peers.push(authority_peer.clone());
        }
        overlay.inbound_routes.push(route);
    }

    if overlay.peers.is_empty() && overlay.inbound_routes.is_empty() {
        return Ok(None);
    }
    overlay.peers.sort_by(|left, right| left.id.cmp(&right.id));
    overlay
        .inbound_routes
        .sort_by(|left, right| left.route_id.cmp(&right.route_id));
    Ok(Some(overlay))
}

pub(super) async fn reconcile_local_framework_routes(
    app: &ControlStateApp,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let overlay_id = framework_route_overlay_id(&app.controller_plan.site_id);
    let endpoint = local_router_control_endpoint(app)?;
    if let Some(overlay) = framework_route_overlay_payload(app).await? {
        apply_route_overlay_with_retry(
            &endpoint,
            &overlay_id,
            &overlay.peers,
            &overlay.inbound_routes,
            Duration::from_secs(30),
        )
        .await
        .map_err(|err| {
            controller_protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &app.controller_plan.site_id,
                "publish framework route overlay",
                err,
            )
        })?;
    } else {
        revoke_route_overlay_with_retry(&endpoint, &overlay_id, Duration::from_secs(30))
            .await
            .map_err(|err| {
                controller_protocol_error(
                    ProtocolErrorCode::ControlStateUnavailable,
                    &app.controller_plan.site_id,
                    "retract framework route overlay",
                    err,
                )
            })?;
    }

    Ok(())
}

fn peer_site_router_url(
    app: &ControlStateApp,
    site_id: &str,
) -> std::result::Result<String, ProtocolErrorResponse> {
    if site_id == app.controller_plan.site_id {
        return Ok(app.controller_plan.authority_url.clone());
    }
    app.controller_plan
        .peer_site_router_urls
        .get(site_id)
        .cloned()
        .ok_or_else(|| {
            protocol_error(
                ProtocolErrorCode::OriginUnavailable,
                &format!(
                    "site controller `{}` has no router forward path to peer site `{site_id}`",
                    app.controller_plan.site_id
                ),
            )
        })
}

async fn peer_controller_post_json_via_router<TReq: Serialize, TResp: for<'de> Deserialize<'de>>(
    app: &ControlStateApp,
    site_id: &str,
    path: &str,
    body: &TReq,
    code: ProtocolErrorCode,
    action: &str,
) -> std::result::Result<TResp, ProtocolErrorResponse> {
    let response = app
        .client
        .post(format!(
            "{}{}",
            peer_site_router_url(app, site_id)?.trim_end_matches('/'),
            path
        ))
        .header(super::site_controller::CONTROLLER_LOCAL_ONLY_HEADER, "1")
        .json(body)
        .send()
        .await
        .map_err(|err| controller_protocol_error(code, site_id, action, err))?;
    if response.status().is_success() {
        return response
            .json()
            .await
            .map_err(|err| controller_protocol_error(code, site_id, action, err));
    }
    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|err| controller_protocol_error(code, site_id, action, err))?;
    if let Ok(protocol_error) = serde_json::from_slice::<ProtocolErrorResponse>(&body) {
        return Err(protocol_error);
    }
    Err(controller_protocol_error(
        code,
        site_id,
        action,
        format!("peer controller returned {status}"),
    ))
}

async fn peer_controller_post_no_content_via_router<TReq: Serialize>(
    app: &ControlStateApp,
    site_id: &str,
    path: &str,
    body: &TReq,
    code: ProtocolErrorCode,
    action: &str,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let response = app
        .client
        .post(format!(
            "{}{}",
            peer_site_router_url(app, site_id)?.trim_end_matches('/'),
            path
        ))
        .header(super::site_controller::CONTROLLER_LOCAL_ONLY_HEADER, "1")
        .json(body)
        .send()
        .await
        .map_err(|err| controller_protocol_error(code, site_id, action, err))?;
    if response.status().is_success() {
        return Ok(());
    }
    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|err| controller_protocol_error(code, site_id, action, err))?;
    if let Ok(protocol_error) = serde_json::from_slice::<ProtocolErrorResponse>(&body) {
        return Err(protocol_error);
    }
    Err(controller_protocol_error(
        code,
        site_id,
        action,
        format!("peer controller returned {status}"),
    ))
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
    if site_id == app.controller_plan.site_id {
        return publish_dynamic_capability_origin_local(
            &LocalDynamicCapabilityOriginApp {
                site_state_root: PathBuf::from(&app.controller_plan.site_state_root),
                runtime: app.runtime.clone(),
            },
            request.clone(),
        )
        .await
        .map_err(|err| err.0);
    }
    let url = format!(
        "{}/v1/internal/dynamic-caps/origins/publish",
        peer_site_router_url(app, site_id)?.trim_end_matches('/')
    );
    let response = app
        .client
        .post(url)
        .header(super::site_controller::CONTROLLER_LOCAL_ONLY_HEADER, "1")
        .json(request)
        .send()
        .await
        .map_err(|err| {
            protocol_error(
                ProtocolErrorCode::OriginUnavailable,
                &format!(
                    "failed to reach site controller on site `{site_id}` through the site router \
                     while publishing dynamic capability origin: {err}"
                ),
            )
        })?;
    if response.status().is_success() {
        return response.json().await.map_err(|err| {
            protocol_error(
                ProtocolErrorCode::OriginUnavailable,
                &format!(
                    "site controller on site `{site_id}` returned invalid JSON through the site \
                     router while publishing dynamic capability origin: {err}"
                ),
            )
        });
    }
    let status = response.status();
    let body = response.bytes().await.map_err(|err| {
        protocol_error(
            ProtocolErrorCode::OriginUnavailable,
            &format!(
                "failed to read site controller error response on site `{site_id}` through the \
                 site router while publishing dynamic capability origin: {err}"
            ),
        )
    })?;
    if let Ok(protocol_error) = serde_json::from_slice::<ProtocolErrorResponse>(&body) {
        return Err(protocol_error);
    }
    Err(protocol_error(
        ProtocolErrorCode::OriginUnavailable,
        &format!(
            "site controller on site `{site_id}` returned {status} through the site router while \
             publishing dynamic capability origin"
        ),
    ))
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

pub(super) async fn prepare_child_on_site(
    app: &ControlStateApp,
    state: &FrameworkControlState,
    child: &LiveChildRecord,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let site_id = child_runtime_site_id(child)?;
    if site_id != app.controller_plan.site_id {
        return Err(controller_protocol_error(
            ProtocolErrorCode::PrepareFailed,
            &site_id,
            "prepare child",
            format!(
                "dynamic child `{}` targeted site `{}` but controller `{}` only creates local \
                 children",
                child.name, site_id, app.controller_plan.site_id
            ),
        ));
    }
    app.runtime
        .prepare_child(&app.controller_plan, state.clone(), child.clone())
        .await
        .map_err(|err| {
            controller_protocol_error(
                ProtocolErrorCode::PrepareFailed,
                &site_id,
                "prepare child",
                err,
            )
        })
}

pub(super) async fn publish_child_on_site(
    app: &ControlStateApp,
    state: &FrameworkControlState,
    child: &LiveChildRecord,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let site_id = child_runtime_site_id(child)?;
    if site_id != app.controller_plan.site_id {
        return Err(controller_protocol_error(
            ProtocolErrorCode::PublishFailed,
            &site_id,
            "publish child",
            format!(
                "dynamic child `{}` targeted site `{}` but controller `{}` only publishes local \
                 children",
                child.name, site_id, app.controller_plan.site_id
            ),
        ));
    }
    app.runtime
        .publish_child(&app.controller_plan, state.clone(), child.clone())
        .await
        .map_err(|err| {
            controller_protocol_error(
                ProtocolErrorCode::PublishFailed,
                &site_id,
                "publish child",
                err,
            )
        })
}

fn site_controller_child_needs_prepare(err: &ProtocolErrorResponse, child_id: u64) -> bool {
    err.code == ProtocolErrorCode::PublishFailed
        && err
            .message
            .contains(&format!("child {child_id} is not prepared"))
}

pub(super) async fn publish_child_on_site_with_prepare_retry(
    app: &ControlStateApp,
    state: &FrameworkControlState,
    child: &LiveChildRecord,
) -> std::result::Result<(), ProtocolErrorResponse> {
    match publish_child_on_site(app, state, child).await {
        Ok(()) => Ok(()),
        Err(err) if site_controller_child_needs_prepare(&err, child.child_id) => {
            prepare_child_on_site(app, state, child).await?;
            publish_child_on_site(app, state, child).await
        }
        Err(err) => Err(err),
    }
}

pub(super) async fn rollback_child_on_site(
    app: &ControlStateApp,
    child_id: u64,
    site_id: &str,
) -> Result<()> {
    if site_id != app.controller_plan.site_id {
        return Err(miette::miette!(
            "dynamic child plan targeted site `{site_id}` but controller `{}` only rolls back \
             local children",
            app.controller_plan.site_id
        ));
    }
    app.runtime
        .rollback_child(&app.controller_plan, child_id)
        .await
}

pub(super) async fn destroy_child_on_site(
    app: &ControlStateApp,
    state: &FrameworkControlState,
    child: &LiveChildRecord,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let site_id = child_runtime_site_id(child)?;
    if site_id != app.controller_plan.site_id {
        return Err(controller_protocol_error(
            ProtocolErrorCode::ControlStateUnavailable,
            &site_id,
            "destroy child",
            format!(
                "dynamic child `{}` targeted site `{site_id}` but controller `{}` only destroys \
                 local children",
                child.name, app.controller_plan.site_id
            ),
        ));
    }
    app.runtime
        .destroy_child(&app.controller_plan, state.clone(), child.clone())
        .await
        .map_err(|err| {
            controller_protocol_error(
                ProtocolErrorCode::ControlStateUnavailable,
                &site_id,
                "destroy child",
                err,
            )
        })
}

pub(super) async fn publish_external_slot_overlay(
    app: &ControlStateApp,
    child: &LiveChildRecord,
    link: &RunLink,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let overlay_id = overlay_id_for_link_action(child, link, |action| {
        matches!(action, DynamicOverlayAction::ExternalSlot { .. })
    })?;
    let consumer_kind = {
        let state = app.control_state.lock().await;
        local_site_kind_from_state(&state, &link.consumer_site)?
    };
    let resolve_request = ResolveExternalLinkUrlRequest {
        child_id: child.child_id,
        link: link.clone(),
        consumer_kind,
    };
    let external_url = if link.provider_site == app.controller_plan.site_id {
        resolve_external_link_url_local(app, &resolve_request)
            .await?
            .external_url
    } else {
        peer_controller_post_json_via_router::<_, ResolveExternalLinkUrlResponse>(
            app,
            &link.provider_site,
            "/v1/internal/link-overlays/external-url",
            &resolve_request,
            ProtocolErrorCode::PublishFailed,
            "resolve provider link url",
        )
        .await?
        .external_url
    };
    let publish_request = PublishExternalSlotOverlayRequest {
        overlay_id: overlay_id.to_string(),
        slot_name: link.external_slot_name.clone(),
        url: external_url,
    };
    if link.consumer_site == app.controller_plan.site_id {
        publish_external_slot_overlay_local(app, &publish_request).await
    } else {
        peer_controller_post_no_content_via_router(
            app,
            &link.consumer_site,
            "/v1/internal/link-overlays/external-slot/publish",
            &publish_request,
            ProtocolErrorCode::PublishFailed,
            "publish external slot overlay",
        )
        .await
    }
}

pub(super) async fn publish_export_peer_overlay(
    app: &ControlStateApp,
    child: &LiveChildRecord,
    link: &RunLink,
) -> std::result::Result<(), ProtocolErrorResponse> {
    let overlay_id = overlay_id_for_link_action(child, link, |action| {
        matches!(action, DynamicOverlayAction::ExportPeer { .. })
    })?;
    let route_id = export_peer_route_id(child, link)?;
    let consumer_identity = if link.consumer_site == app.controller_plan.site_id {
        local_router_identity_for_overlay(app).await?
    } else {
        peer_router_identity_for_overlay(app, &link.consumer_site).await?
    };
    let publish_request = PublishExportPeerOverlayRequest {
        overlay_id: overlay_id.to_string(),
        export_name: link.export_name.clone(),
        peer_id: consumer_identity.id,
        peer_key_b64: base64::engine::general_purpose::STANDARD
            .encode(consumer_identity.public_key),
        protocol: link.protocol.to_string(),
        route_id: Some(route_id),
    };
    if link.provider_site == app.controller_plan.site_id {
        publish_export_peer_overlay_local(app, &publish_request).await
    } else {
        peer_controller_post_no_content_via_router(
            app,
            &link.provider_site,
            "/v1/internal/link-overlays/export-peer/publish",
            &publish_request,
            ProtocolErrorCode::PublishFailed,
            "publish export-peer overlay",
        )
        .await
    }
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
    site_controller_runtime_child_root_for_site(local_site_state_root(app), child.child_id)
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
    {
        let state = app.control_state.lock().await;
        if link_still_required(&state, child_id, link) {
            return Ok(());
        }
    }
    let clear_request = ClearExternalSlotOverlayRequest {
        overlay_id: overlay_id.to_string(),
        slot_name: link.external_slot_name.clone(),
    };
    if link.consumer_site == app.controller_plan.site_id {
        clear_external_slot_overlay_local(app, &clear_request).await
    } else {
        peer_controller_post_no_content_via_router(
            app,
            &link.consumer_site,
            "/v1/internal/link-overlays/external-slot/clear",
            &clear_request,
            ProtocolErrorCode::ControlStateUnavailable,
            "retract external slot overlay",
        )
        .await
    }
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
    {
        let state = app.control_state.lock().await;
        if link_still_required(&state, child_id, link) {
            return Ok(());
        }
    }
    let route_id = export_peer_route_id(child, link)?;
    let consumer_identity = if link.consumer_site == app.controller_plan.site_id {
        local_router_identity_for_overlay(app).await?
    } else {
        peer_router_identity_for_overlay(app, &link.consumer_site).await?
    };
    let clear_request = ClearExportPeerOverlayRequest {
        overlay_id: overlay_id.to_string(),
        export_name: link.export_name.clone(),
        peer_id: consumer_identity.id,
        peer_key_b64: base64::engine::general_purpose::STANDARD
            .encode(consumer_identity.public_key),
        protocol: link.protocol.to_string(),
        route_id: Some(route_id),
    };
    if link.provider_site == app.controller_plan.site_id {
        clear_export_peer_overlay_local(app, &clear_request).await
    } else {
        peer_controller_post_no_content_via_router(
            app,
            &link.provider_site,
            "/v1/internal/link-overlays/export-peer/clear",
            &clear_request,
            ProtocolErrorCode::ControlStateUnavailable,
            "retract export-peer overlay",
        )
        .await
    }
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
        let revoke_request = RevokeDynamicCapabilityOriginOverlaysRequest {
            overlay_ids: overlay_ids.into_iter().collect(),
        };
        if site_id == app.controller_plan.site_id {
            revoke_dynamic_capability_origin_overlays_local(app, &revoke_request).await?;
        } else {
            peer_controller_post_no_content_via_router(
                app,
                &site_id,
                "/v1/internal/dynamic-caps/origins/revoke",
                &revoke_request,
                ProtocolErrorCode::ControlStateUnavailable,
                "retract dynamic capability origin overlays",
            )
            .await?;
        }
    }

    Ok(())
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
    prepared: bool,
) -> Result<()> {
    if prepared {
        rollback_child_on_site(app, child_id, &app.controller_plan.site_id).await?;
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

    let state = app.control_state.lock().await.clone();
    let published_links = child_link_records(&child);
    for link in &published_links {
        publish_link_overlays(app, &child, link).await?;
    }
    if let Err(err) = publish_child_on_site_with_prepare_retry(app, &state, &child).await {
        let mut cleanup_error = None;
        for link in published_links.iter().rev() {
            if let Err(retract_err) = retract_link_overlays(app, &child, link).await
                && cleanup_error.is_none()
            {
                cleanup_error = Some(retract_err);
            }
        }
        if let Err(destroy_err) = destroy_child_on_site(app, &state, &child).await
            && cleanup_error.is_none()
        {
            cleanup_error = Some(destroy_err);
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
            persist_control_state_update(&mut state, &app.state_path, "create_aborted", |state| {
                append_journal_entry(state, tx_id, &child, ChildState::CreateAborted);
                remove_child_record(state, child.child_id)?;
                Ok(())
            })?;
        }
        return Err(err);
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
    let state = app.control_state.lock().await.clone();
    destroy_child_on_site(app, &state, &child).await?;

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
    reconcile_local_framework_routes(app).await?;

    let state = app.control_state.lock().await.clone();
    if let Err(err) = prepare_child_on_site(app, &state, &child).await {
        let rollback_err = rollback_prepared_sites(app, child.child_id, false).await;
        let should_reconcile = {
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
                true
            } else {
                false
            }
        };
        if should_reconcile {
            reconcile_local_framework_routes(app).await?;
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
    let (next, reconcile_routes) = {
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
                ((child.child_id, ChildState::DestroyRequested), true)
            }
            ChildState::DestroyRequested => ((child.child_id, ChildState::DestroyRequested), false),
            ChildState::DestroyRetracted => ((child.child_id, ChildState::DestroyRetracted), false),
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
    if reconcile_routes {
        reconcile_local_framework_routes(app).await?;
    }
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
                rollback_prepared_sites(app, child.child_id, true)
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
    reconcile_local_framework_routes(app)
        .await
        .map_err(|err| miette::miette!(err.message))?;
    Ok(())
}
