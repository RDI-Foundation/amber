use std::sync::Arc;

use amber_mesh::{MeshIdentityPublic, dynamic_caps::HeldListResponse};
use amber_proxy::{ControlEndpoint, fetch_router_identity};
use axum::{
    Json, Router,
    extract::{Path as AxumPath, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use base64::Engine as _;
use miette::{IntoDiagnostic as _, Result, WrapErr as _};
use reqwest::Client as ReqwestClient;
use serde::{Serialize, de::DeserializeOwned};
use tokio::net::TcpListener;

use super::{
    ccs_api::{self, FrameworkComponentInspectRequest, FrameworkComponentInspectResponse},
    control_state_api::{
        self, DynamicCapsInspectRequest, DynamicCapsInspectResponse, DynamicCapsMutateRequest,
        DynamicCapsMutateResponse, local_component_runtime,
        resolve_dynamic_capability_origin_internal,
    },
    dynamic_caps::{
        self, ControlDynamicHeldDetailRequest, ControlDynamicHeldListRequest,
        ControlDynamicInspectRefRequest, ControlDynamicResolveOriginRequest,
        ControlDynamicRevokeRequest, ControlDynamicShareRequest,
        InternalDynamicResolveOriginRequest,
    },
    http::{
        authorize_framework_auth_header, cleanup_dynamic_bridge_proxies, healthz, read_json,
        required_header, shutdown_signal,
    },
    orchestration::{
        ClearExportPeerOverlayRequest, ClearExternalSlotOverlayRequest, ProtocolApiError,
        PublishExportPeerOverlayRequest, PublishExternalSlotOverlayRequest,
        ResolveExternalLinkUrlRequest, ResolveExternalLinkUrlResponse,
        RevokeDynamicCapabilityOriginOverlaysRequest, clear_export_peer_overlay_local,
        clear_external_slot_overlay_local, execute_create_child, execute_destroy_child,
        publish_dynamic_capability_origin_local, publish_export_peer_overlay_local,
        publish_external_slot_overlay_local, recover_control_state,
        resolve_external_link_url_local, revoke_dynamic_capability_origin_overlays_local,
    },
    planner::{
        ControlStateApp, LocalDynamicCapabilityOriginApp, SiteControllerApp, protocol_error,
    },
    state::*,
    *,
};
use crate::runtime_api::SharedSiteControllerRuntime;

pub(crate) const CONTROLLER_LOCAL_ONLY_HEADER: &str = "x-amber-site-controller-local-only";

pub(crate) async fn run_site_controller(
    plan_path: PathBuf,
    runtime: SharedSiteControllerRuntime,
) -> Result<()> {
    let plan: SiteControllerPlan = read_json(plan_path.as_path(), "site controller plan")?;
    let mut control_state: FrameworkControlState =
        read_json(Path::new(&plan.state_path), "site controller state file")?;
    persist_control_state(Path::new(&plan.state_path), &mut control_state)?;
    let control = ControlStateApp {
        control_state: Arc::new(Mutex::new(control_state)),
        client: ReqwestClient::new(),
        state_path: PathBuf::from(&plan.state_path),
        run_root: PathBuf::from(&plan.run_root),
        state_root: PathBuf::from(&plan.state_root),
        mesh_scope: Arc::<str>::from(plan.mesh_scope.clone()),
        control_state_auth_token: Arc::<str>::from(plan.auth_token.clone()),
        controller_plan: Arc::new(plan.clone()),
        authority_locks: Arc::new(Mutex::new(BTreeMap::new())),
        runtime,
    };
    let app_state = SiteControllerApp {
        control: control.clone(),
        router_auth_token: Arc::<str>::from(plan.auth_token),
    };
    recover_control_state(&control).await?;
    let app = site_controller_router(app_state.clone());
    let listener = TcpListener::bind(plan.listen_addr)
        .await
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to bind site controller on {}", plan.listen_addr))?;
    let serve_result = axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .into_diagnostic();
    let cleanup_result = cleanup_dynamic_bridge_proxies(&control).await;
    match (serve_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(err), Ok(())) => Err(err).wrap_err("site controller failed"),
        (Ok(()), Err(err)) => Err(err).wrap_err("site controller failed to stop bridge proxies"),
        (Err(serve_err), Err(cleanup_err)) => Err(miette::miette!(
            "site controller failed: {serve_err}\nbridge proxy cleanup failed: {cleanup_err}"
        )),
    }
}

pub(crate) fn site_controller_router(app_state: SiteControllerApp) -> Router {
    Router::new()
        .nest_service("/mcp", super::mcp::service(app_state.clone()))
        .nest_service(
            "/v1/controller/dynamic-caps/mcp",
            super::control_state_mcp::service(app_state.clone()),
        )
        .route("/", get(healthz))
        .route("/healthz", get(healthz))
        .route(
            SITE_CONTROLLER_STATE_PATH,
            get(get_site_controller_state_route),
        )
        .route(
            "/v1/controller/router-identity",
            get(get_router_identity_route),
        )
        .route("/v1/templates", get(list_templates))
        .route("/v1/templates/{template}", get(describe_template))
        .route("/v1/templates/{template}/resolve", post(resolve_template))
        .route("/v1/children", get(list_children).post(create_child))
        .route(
            "/v1/children/{child}",
            get(describe_child).delete(destroy_child),
        )
        .route("/v1/snapshot", post(snapshot))
        .route(
            "/v1/internal/dynamic-caps/origins/publish",
            post(publish_dynamic_origin),
        )
        .route(
            "/v1/internal/dynamic-caps/resolve-origin",
            post(resolve_dynamic_origin_internal_route),
        )
        .route(
            "/v1/internal/dynamic-caps/origins/revoke",
            post(revoke_dynamic_origin_overlays),
        )
        .route(
            "/v1/internal/link-overlays/external-url",
            post(resolve_external_link_url),
        )
        .route(
            "/v1/internal/link-overlays/external-slot/publish",
            post(publish_external_slot_overlay_route),
        )
        .route(
            "/v1/internal/link-overlays/external-slot/clear",
            post(clear_external_slot_overlay_route),
        )
        .route(
            "/v1/internal/link-overlays/export-peer/publish",
            post(publish_export_peer_overlay_route),
        )
        .route(
            "/v1/internal/link-overlays/export-peer/clear",
            post(clear_export_peer_overlay_route),
        )
        .route(
            "/v1/controller/dynamic-caps/held",
            post(control_dynamic_held_list_route),
        )
        .route(
            "/v1/controller/dynamic-caps/held/detail",
            post(control_dynamic_held_detail_route),
        )
        .route(
            "/v1/controller/dynamic-caps/share",
            post(control_dynamic_share_route),
        )
        .route(
            "/v1/controller/dynamic-caps/inspect-ref",
            post(control_dynamic_inspect_ref_route),
        )
        .route(
            "/v1/controller/dynamic-caps/revoke",
            post(control_dynamic_revoke_route),
        )
        .route(
            "/v1/controller/dynamic-caps/resolve-origin",
            post(control_dynamic_resolve_origin_route),
        )
        .with_state(app_state)
}

async fn get_site_controller_state_route(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
) -> std::result::Result<Json<FrameworkControlState>, ProtocolApiError> {
    authorize_framework_auth_header(&headers, app.control.control_state_auth_token.as_ref())?;
    Ok(Json(app.control.control_state.lock().await.clone()))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RouterIdentityResponse {
    pub(crate) id: String,
    pub(crate) public_key_b64: String,
}

fn authorize_local_controller_request(
    app: &SiteControllerApp,
    headers: &HeaderMap,
) -> std::result::Result<(), ProtocolApiError> {
    authorize_framework_auth_header(headers, app.router_auth_token.as_ref())?;
    if !controller_local_only(headers) {
        return Err(ProtocolApiError::unauthorized(
            "local controller endpoint requires router-local forwarding".to_string(),
        ));
    }
    Ok(())
}

fn local_router_control_endpoint(
    app: &SiteControllerApp,
) -> std::result::Result<ControlEndpoint, ProtocolApiError> {
    if let Some(raw) = app.control.controller_plan.local_router_control.as_deref() {
        return parse_control_endpoint(raw).map_err(|err| {
            ProtocolApiError::control_state_unavailable(format!(
                "site controller local router control endpoint is invalid: {err}"
            ))
        });
    }
    let manager_state_path =
        Path::new(&app.control.controller_plan.site_state_root).join("manager-state.json");
    if manager_state_path.is_file() {
        let state: super::planner::SiteManagerStateView =
            read_json(&manager_state_path, "site manager state").map_err(|err| {
                ProtocolApiError::control_state_unavailable(format!(
                    "site manager state is unavailable: {err}"
                ))
            })?;
        if let Some(raw) = state.router_control {
            return parse_control_endpoint(&raw).map_err(|err| {
                ProtocolApiError::control_state_unavailable(format!(
                    "site manager state has an invalid router control endpoint: {err}"
                ))
            });
        }
    }
    Err(ProtocolApiError::control_state_unavailable(
        "site controller local router control endpoint is unavailable".to_string(),
    ))
}

async fn get_router_identity_route(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
) -> std::result::Result<Json<RouterIdentityResponse>, ProtocolApiError> {
    authorize_local_controller_request(&app, &headers)?;
    let endpoint = local_router_control_endpoint(&app)?;
    let identity = fetch_router_identity(&endpoint).await.map_err(|err| {
        ProtocolApiError::control_state_unavailable(format!(
            "failed to read local router identity: {err}"
        ))
    })?;
    Ok(Json(RouterIdentityResponse {
        id: identity.id,
        public_key_b64: base64::engine::general_purpose::STANDARD.encode(identity.public_key),
    }))
}

pub(super) async fn authorize_public_request(
    app: &SiteControllerApp,
    headers: &HeaderMap,
) -> std::result::Result<(CapabilityInstanceRecord, FrameworkControlState), ProtocolApiError> {
    authorize_framework_auth_header(headers, app.router_auth_token.as_ref())?;
    let route_id = required_header(headers, FRAMEWORK_ROUTE_ID_HEADER)?;
    let peer_id = required_header(headers, FRAMEWORK_PEER_ID_HEADER)?;
    let state = app.control.control_state.lock().await.clone();
    let record = super::api::authorize_capability_instance(&state, &route_id, &peer_id)
        .map_err(ProtocolApiError::from)?
        .clone();
    Ok((record, state))
}

fn controller_local_only(headers: &HeaderMap) -> bool {
    headers
        .get(CONTROLLER_LOCAL_ONLY_HEADER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == "1")
}

fn peer_site_router_url_for_site(
    app: &SiteControllerApp,
    site_id: &str,
) -> std::result::Result<String, ProtocolApiError> {
    app.control
        .controller_plan
        .peer_site_router_urls
        .get(site_id)
        .cloned()
        .ok_or_else(|| {
            ProtocolApiError::control_state_unavailable(format!(
                "site controller `{}` has no router forward path to peer site `{site_id}`",
                app.control.controller_plan.site_id
            ))
        })
}

fn peer_site_ids(app: &SiteControllerApp) -> Vec<String> {
    app.control
        .controller_plan
        .peer_site_router_urls
        .keys()
        .cloned()
        .collect()
}

async fn peer_dynamic_caps_post_via_router<TReq: Serialize, TResp: DeserializeOwned>(
    app: &SiteControllerApp,
    site_id: &str,
    path: &str,
    body: &TReq,
) -> std::result::Result<TResp, ProtocolApiError> {
    let response = app
        .control
        .client
        .post(format!(
            "{}{}",
            peer_site_router_url_for_site(app, site_id)?.trim_end_matches('/'),
            path
        ))
        .header(CONTROLLER_LOCAL_ONLY_HEADER, "1")
        .json(body)
        .send()
        .await
        .map_err(|err| {
            ProtocolApiError::control_state_unavailable(format!(
                "failed to reach site controller for site `{site_id}` through site router: {err}"
            ))
        })?;
    if response.status().is_success() {
        return response.json().await.map_err(|err| {
            ProtocolApiError::control_state_unavailable(format!(
                "site controller for site `{site_id}` returned invalid JSON through site router: \
                 {err}"
            ))
        });
    }
    let status = response.status();
    let body = response.bytes().await.map_err(|err| {
        ProtocolApiError::control_state_unavailable(format!(
            "failed to read site controller error response for site `{site_id}`: {err}"
        ))
    })?;
    if let Ok(protocol_error) = serde_json::from_slice::<ProtocolErrorResponse>(&body) {
        return Err(protocol_error.into());
    }
    Err(ProtocolApiError::control_state_unavailable(format!(
        "site controller for site `{site_id}` returned {status} through site router"
    )))
}

async fn peer_controller_get_via_router<TResp: DeserializeOwned>(
    app: &SiteControllerApp,
    site_id: &str,
    path: &str,
) -> std::result::Result<TResp, ProtocolApiError> {
    let response = app
        .control
        .client
        .get(format!(
            "{}{}",
            peer_site_router_url_for_site(app, site_id)?.trim_end_matches('/'),
            path
        ))
        .header(CONTROLLER_LOCAL_ONLY_HEADER, "1")
        .send()
        .await
        .map_err(|err| {
            ProtocolApiError::control_state_unavailable(format!(
                "failed to reach site controller for site `{site_id}` through site router: {err}"
            ))
        })?;
    if response.status().is_success() {
        return response.json().await.map_err(|err| {
            ProtocolApiError::control_state_unavailable(format!(
                "site controller for site `{site_id}` returned invalid JSON through site router: \
                 {err}"
            ))
        });
    }
    let status = response.status();
    let body = response.bytes().await.map_err(|err| {
        ProtocolApiError::control_state_unavailable(format!(
            "failed to read site controller error response for site `{site_id}`: {err}"
        ))
    })?;
    if let Ok(protocol_error) = serde_json::from_slice::<ProtocolErrorResponse>(&body) {
        return Err(protocol_error.into());
    }
    Err(ProtocolApiError::control_state_unavailable(format!(
        "site controller for site `{site_id}` returned {status} through site router"
    )))
}

pub(super) async fn peer_router_identity_via_router(
    app: &SiteControllerApp,
    site_id: &str,
) -> std::result::Result<MeshIdentityPublic, ProtocolApiError> {
    let response: RouterIdentityResponse =
        peer_controller_get_via_router(app, site_id, "/v1/controller/router-identity").await?;
    let public_key = base64::engine::general_purpose::STANDARD
        .decode(response.public_key_b64)
        .map_err(|err| {
            ProtocolApiError::control_state_unavailable(format!(
                "site controller for site `{site_id}` returned an invalid router public key: {err}"
            ))
        })?;
    let public_key: [u8; 32] = public_key.try_into().map_err(|_| {
        ProtocolApiError::control_state_unavailable(format!(
            "site controller for site `{site_id}` returned a router public key with the wrong \
             length"
        ))
    })?;
    Ok(MeshIdentityPublic {
        id: response.id,
        public_key,
        mesh_scope: Some(app.control.mesh_scope.to_string()),
    })
}

async fn local_held_list(
    app: &SiteControllerApp,
    request: ControlDynamicHeldListRequest,
) -> std::result::Result<HeldListResponse, ProtocolApiError> {
    match control_state_api::execute_dynamic_caps_inspect(
        &app.control,
        DynamicCapsInspectRequest::HeldList(request),
    )
    .await?
    {
        DynamicCapsInspectResponse::HeldList(response) => Ok(response),
        _ => unreachable!("held_list should return held list"),
    }
}

async fn local_held_detail(
    app: &SiteControllerApp,
    request: ControlDynamicHeldDetailRequest,
) -> std::result::Result<HeldEntryDetail, ProtocolApiError> {
    match control_state_api::execute_dynamic_caps_inspect(
        &app.control,
        DynamicCapsInspectRequest::HeldDetail(request),
    )
    .await?
    {
        DynamicCapsInspectResponse::HeldDetail(response) => Ok(response),
        _ => unreachable!("held_detail should return held detail"),
    }
}

async fn local_inspect_ref(
    app: &SiteControllerApp,
    request: ControlDynamicInspectRefRequest,
) -> std::result::Result<amber_mesh::dynamic_caps::InspectRefResponse, ProtocolApiError> {
    match control_state_api::execute_dynamic_caps_inspect(
        &app.control,
        DynamicCapsInspectRequest::InspectRef(request),
    )
    .await?
    {
        DynamicCapsInspectResponse::InspectRef(response) => Ok(response),
        _ => unreachable!("inspect_ref should return inspect response"),
    }
}

async fn local_resolve_origin(
    app: &SiteControllerApp,
    request: ControlDynamicResolveOriginRequest,
) -> std::result::Result<dynamic_caps::ControlDynamicResolveOriginResponse, ProtocolApiError> {
    match control_state_api::execute_dynamic_caps_inspect(
        &app.control,
        DynamicCapsInspectRequest::ResolveOrigin(request),
    )
    .await?
    {
        DynamicCapsInspectResponse::ResolveOrigin(response) => Ok(response),
        _ => unreachable!("resolve_origin should return origin resolution"),
    }
}

async fn local_share(
    app: &SiteControllerApp,
    request: ControlDynamicShareRequest,
) -> std::result::Result<amber_mesh::dynamic_caps::ShareResponse, ProtocolApiError> {
    match control_state_api::execute_dynamic_caps_mutate(
        &app.control,
        DynamicCapsMutateRequest::Share(request),
    )
    .await?
    {
        DynamicCapsMutateResponse::Share(response) => Ok(response),
        _ => unreachable!("share should return share response"),
    }
}

async fn local_revoke(
    app: &SiteControllerApp,
    request: ControlDynamicRevokeRequest,
) -> std::result::Result<amber_mesh::dynamic_caps::RevokeResponse, ProtocolApiError> {
    match control_state_api::execute_dynamic_caps_mutate(
        &app.control,
        DynamicCapsMutateRequest::Revoke(request),
    )
    .await?
    {
        DynamicCapsMutateResponse::Revoke(response) => Ok(response),
        _ => unreachable!("revoke should return revoke response"),
    }
}

fn site_for_dynamic_source(
    state: &FrameworkControlState,
    source: &dynamic_caps::DynamicCapabilityControlSourceRequest,
) -> std::result::Result<String, ProtocolApiError> {
    match source {
        dynamic_caps::DynamicCapabilityControlSourceRequest::RootAuthority {
            root_authority_selector,
        } => site_id_for_root_authority_selector(state, root_authority_selector),
        dynamic_caps::DynamicCapabilityControlSourceRequest::Grant { grant_id } => {
            site_id_for_dynamic_grant(state, grant_id)
        }
    }
    .map_err(ProtocolApiError::from)
}

fn site_for_held_id(
    state: &FrameworkControlState,
    held_id: &str,
) -> std::result::Result<String, ProtocolApiError> {
    match dynamic_caps::parse_held_entry_key(held_id).map_err(ProtocolApiError::from)? {
        dynamic_caps::HeldEntryKey::RootAuthority(selector) => {
            site_id_for_root_authority_selector(state, &selector)
        }
        dynamic_caps::HeldEntryKey::Grant(grant_id) => site_id_for_dynamic_grant(state, &grant_id),
    }
    .map_err(ProtocolApiError::from)
}

fn site_for_dynamic_ref(
    state: &FrameworkControlState,
    raw_ref: &str,
) -> std::result::Result<String, ProtocolApiError> {
    let parsed = amber_mesh::dynamic_caps::decode_dynamic_capability_ref_unverified(raw_ref)
        .map_err(|err| {
            ProtocolApiError::from(protocol_error(
                ProtocolErrorCode::MalformedRef,
                &format!("dynamic capability ref is malformed: {err}"),
            ))
        })?;
    site_id_for_dynamic_grant(state, &parsed.claims.grant_id).map_err(ProtocolApiError::from)
}

fn framework_request_site_id(
    state: &FrameworkControlState,
    record: &CapabilityInstanceRecord,
) -> std::result::Result<String, ProtocolApiError> {
    match site_id_for_authority_realm(state, record.authority_realm_id) {
        Ok(site_id) => Ok(site_id),
        Err(_) => Ok(record.recipient_site_id.clone()),
    }
}

pub(super) async fn execute_site_controller_framework_inspect(
    app: &SiteControllerApp,
    record: &CapabilityInstanceRecord,
    state: &FrameworkControlState,
    request: FrameworkComponentInspectRequest,
) -> std::result::Result<FrameworkComponentInspectResponse, ProtocolApiError> {
    let authority_site = framework_request_site_id(state, record)?;
    if authority_site != app.control.controller_plan.site_id {
        return Err(ProtocolApiError::control_state_unavailable(format!(
            "framework.component request for authority site `{authority_site}` reached site \
             controller `{}`; router framework route overlays are stale",
            app.control.controller_plan.site_id
        )));
    }

    ccs_api::execute_framework_component_inspect(state, record.authority_realm_id, request)
        .await
        .map_err(ProtocolApiError::from)
}

pub(super) async fn execute_site_controller_framework_mutate(
    app: &SiteControllerApp,
    record: &CapabilityInstanceRecord,
    state: &FrameworkControlState,
    request: ccs_api::FrameworkComponentMutateRequest,
) -> std::result::Result<ccs_api::FrameworkComponentMutateResponse, ProtocolApiError> {
    let authority_site = framework_request_site_id(state, record)?;
    if authority_site != app.control.controller_plan.site_id {
        return Err(ProtocolApiError::control_state_unavailable(format!(
            "framework.component request for authority site `{authority_site}` reached site \
             controller `{}`; router framework route overlays are stale",
            app.control.controller_plan.site_id
        )));
    }

    match request {
        ccs_api::FrameworkComponentMutateRequest::CreateChild(request) => {
            Ok(ccs_api::FrameworkComponentMutateResponse::CreateChild(
                execute_create_child(&app.control, record.authority_realm_id, request).await?,
            ))
        }
        ccs_api::FrameworkComponentMutateRequest::DestroyChild { child } => {
            execute_destroy_child(&app.control, record.authority_realm_id, &child).await?;
            Ok(ccs_api::FrameworkComponentMutateResponse::DestroyChild(
                ccs_api::DestroyChildResponse {
                    child,
                    destroyed: true,
                },
            ))
        }
    }
}

pub(super) async fn execute_site_controller_dynamic_caps_inspect(
    app: &SiteControllerApp,
    request: DynamicCapsInspectRequest,
    local_only: bool,
) -> std::result::Result<DynamicCapsInspectResponse, ProtocolApiError> {
    match request {
        DynamicCapsInspectRequest::HeldList(request) => {
            if local_only {
                return Ok(DynamicCapsInspectResponse::HeldList(
                    local_held_list(app, request).await?,
                ));
            }
            let mut held = local_held_list(app, request.clone()).await?.held;
            for site_id in peer_site_ids(app) {
                held.extend(
                    peer_dynamic_caps_post_via_router::<_, HeldListResponse>(
                        app,
                        &site_id,
                        "/v1/controller/dynamic-caps/held",
                        &request,
                    )
                    .await?
                    .held,
                );
            }
            held.sort_by(|left, right| left.held_id.cmp(&right.held_id));
            Ok(DynamicCapsInspectResponse::HeldList(HeldListResponse {
                held,
            }))
        }
        DynamicCapsInspectRequest::HeldDetail(request) => {
            if local_only {
                return Ok(DynamicCapsInspectResponse::HeldDetail(
                    local_held_detail(app, request).await?,
                ));
            }
            let state = app.control.control_state.lock().await.clone();
            let site_id = site_for_held_id(&state, &request.held_id)?;
            if site_id == app.control.controller_plan.site_id {
                return Ok(DynamicCapsInspectResponse::HeldDetail(
                    local_held_detail(app, request).await?,
                ));
            }
            Ok(DynamicCapsInspectResponse::HeldDetail(
                peer_dynamic_caps_post_via_router(
                    app,
                    &site_id,
                    "/v1/controller/dynamic-caps/held/detail",
                    &request,
                )
                .await?,
            ))
        }
        DynamicCapsInspectRequest::InspectRef(request) => {
            if local_only {
                return Ok(DynamicCapsInspectResponse::InspectRef(
                    local_inspect_ref(app, request).await?,
                ));
            }
            let state = app.control.control_state.lock().await.clone();
            let site_id = site_for_dynamic_ref(&state, &request.r#ref)?;
            if site_id == app.control.controller_plan.site_id {
                return Ok(DynamicCapsInspectResponse::InspectRef(
                    local_inspect_ref(app, request).await?,
                ));
            }
            Ok(DynamicCapsInspectResponse::InspectRef(
                peer_dynamic_caps_post_via_router(
                    app,
                    &site_id,
                    "/v1/controller/dynamic-caps/inspect-ref",
                    &request,
                )
                .await?,
            ))
        }
        DynamicCapsInspectRequest::ResolveOrigin(request) => {
            if local_only {
                return Ok(DynamicCapsInspectResponse::ResolveOrigin(
                    local_resolve_origin(app, request).await?,
                ));
            }
            let state = app.control.control_state.lock().await.clone();
            let site_id = site_for_dynamic_source(&state, &request.source)?;
            if site_id == app.control.controller_plan.site_id {
                return Ok(DynamicCapsInspectResponse::ResolveOrigin(
                    local_resolve_origin(app, request).await?,
                ));
            }
            let holder_runtime =
                local_component_runtime(&app.control, &state, &request.holder_component_id)
                    .map_err(ProtocolApiError::from)?;
            Ok(DynamicCapsInspectResponse::ResolveOrigin(
                peer_dynamic_caps_post_via_router(
                    app,
                    &site_id,
                    "/v1/internal/dynamic-caps/resolve-origin",
                    &InternalDynamicResolveOriginRequest {
                        holder_component_id: request.holder_component_id,
                        source: request.source,
                        holder_peer_id: holder_runtime.mesh_config.identity.id.clone(),
                        holder_peer_key_b64: base64::engine::general_purpose::STANDARD
                            .encode(holder_runtime.mesh_config.identity.public_key),
                        holder_site_kind: app.control.controller_plan.kind,
                    },
                )
                .await?,
            ))
        }
    }
}

pub(super) async fn execute_site_controller_dynamic_caps_mutate(
    app: &SiteControllerApp,
    request: DynamicCapsMutateRequest,
    local_only: bool,
) -> std::result::Result<DynamicCapsMutateResponse, ProtocolApiError> {
    match request {
        DynamicCapsMutateRequest::Share(request) => {
            if local_only {
                return Ok(DynamicCapsMutateResponse::Share(
                    local_share(app, request).await?,
                ));
            }
            let state = app.control.control_state.lock().await.clone();
            let site_id = site_for_dynamic_source(&state, &request.source)?;
            if site_id == app.control.controller_plan.site_id {
                return Ok(DynamicCapsMutateResponse::Share(
                    local_share(app, request).await?,
                ));
            }
            Ok(DynamicCapsMutateResponse::Share(
                peer_dynamic_caps_post_via_router(
                    app,
                    &site_id,
                    "/v1/controller/dynamic-caps/share",
                    &request,
                )
                .await?,
            ))
        }
        DynamicCapsMutateRequest::Revoke(request) => {
            if local_only {
                return Ok(DynamicCapsMutateResponse::Revoke(
                    local_revoke(app, request).await?,
                ));
            }
            let state = app.control.control_state.lock().await.clone();
            let site_id = site_for_dynamic_source(&state, &request.target)?;
            if site_id == app.control.controller_plan.site_id {
                return Ok(DynamicCapsMutateResponse::Revoke(
                    local_revoke(app, request).await?,
                ));
            }
            Ok(DynamicCapsMutateResponse::Revoke(
                peer_dynamic_caps_post_via_router(
                    app,
                    &site_id,
                    "/v1/controller/dynamic-caps/revoke",
                    &request,
                )
                .await?,
            ))
        }
    }
}

async fn list_templates(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
) -> std::result::Result<Json<TemplateListResponse>, ProtocolApiError> {
    let (record, state) = authorize_public_request(&app, &headers).await?;
    match execute_site_controller_framework_inspect(
        &app,
        &record,
        &state,
        FrameworkComponentInspectRequest::ListTemplates,
    )
    .await?
    {
        FrameworkComponentInspectResponse::ListTemplates(response) => Ok(Json(response)),
        _ => unreachable!("list_templates should return template list"),
    }
}

async fn describe_template(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    AxumPath(template): AxumPath<String>,
) -> std::result::Result<Json<TemplateDescribeResponse>, ProtocolApiError> {
    let (record, state) = authorize_public_request(&app, &headers).await?;
    match execute_site_controller_framework_inspect(
        &app,
        &record,
        &state,
        FrameworkComponentInspectRequest::GetTemplate { template },
    )
    .await?
    {
        FrameworkComponentInspectResponse::GetTemplate(response) => Ok(Json(response)),
        _ => unreachable!("get_template should return template description"),
    }
}

async fn resolve_template(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    AxumPath(template): AxumPath<String>,
    Json(request): Json<TemplateResolveRequest>,
) -> std::result::Result<Json<TemplateDescribeResponse>, ProtocolApiError> {
    let (record, state) = authorize_public_request(&app, &headers).await?;
    match execute_site_controller_framework_inspect(
        &app,
        &record,
        &state,
        FrameworkComponentInspectRequest::ResolveTemplate { template, request },
    )
    .await?
    {
        FrameworkComponentInspectResponse::ResolveTemplate(response) => Ok(Json(response)),
        _ => unreachable!("resolve_template should return resolved template"),
    }
}

async fn list_children(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
) -> std::result::Result<Json<ChildListResponse>, ProtocolApiError> {
    let (record, state) = authorize_public_request(&app, &headers).await?;
    match execute_site_controller_framework_inspect(
        &app,
        &record,
        &state,
        FrameworkComponentInspectRequest::ListChildren,
    )
    .await?
    {
        FrameworkComponentInspectResponse::ListChildren(response) => Ok(Json(response)),
        _ => unreachable!("list_children should return child list"),
    }
}

async fn create_child(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    Json(request): Json<CreateChildRequest>,
) -> std::result::Result<Json<CreateChildResponse>, ProtocolApiError> {
    let (record, state) = authorize_public_request(&app, &headers).await?;
    match execute_site_controller_framework_mutate(
        &app,
        &record,
        &state,
        ccs_api::FrameworkComponentMutateRequest::CreateChild(request),
    )
    .await?
    {
        ccs_api::FrameworkComponentMutateResponse::CreateChild(response) => Ok(Json(response)),
        _ => unreachable!("create_child should return create response"),
    }
}

async fn describe_child(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    AxumPath(child): AxumPath<String>,
) -> std::result::Result<Json<ChildDescribeResponse>, ProtocolApiError> {
    let (record, state) = authorize_public_request(&app, &headers).await?;
    match execute_site_controller_framework_inspect(
        &app,
        &record,
        &state,
        FrameworkComponentInspectRequest::GetChild { child },
    )
    .await?
    {
        FrameworkComponentInspectResponse::GetChild(response) => Ok(Json(response)),
        _ => unreachable!("get_child should return child description"),
    }
}

async fn snapshot(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
) -> std::result::Result<Json<SnapshotResponse>, ProtocolApiError> {
    let (record, state) = authorize_public_request(&app, &headers).await?;
    match execute_site_controller_framework_inspect(
        &app,
        &record,
        &state,
        FrameworkComponentInspectRequest::GetSnapshot,
    )
    .await?
    {
        FrameworkComponentInspectResponse::GetSnapshot(response) => Ok(Json(response)),
        _ => unreachable!("get_snapshot should return snapshot"),
    }
}

async fn destroy_child(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    AxumPath(child): AxumPath<String>,
) -> std::result::Result<StatusCode, ProtocolApiError> {
    let (record, state) = authorize_public_request(&app, &headers).await?;
    let _ = execute_site_controller_framework_mutate(
        &app,
        &record,
        &state,
        ccs_api::FrameworkComponentMutateRequest::DestroyChild { child },
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn publish_dynamic_origin(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    Json(request): Json<dynamic_caps::PublishDynamicCapabilityOriginRequest>,
) -> std::result::Result<Json<dynamic_caps::PublishDynamicCapabilityOriginResponse>, ProtocolApiError>
{
    authorize_local_controller_request(&app, &headers)?;
    let ccs_app = LocalDynamicCapabilityOriginApp {
        site_state_root: PathBuf::from(&app.control.controller_plan.site_state_root),
        runtime: app.control.runtime.clone(),
    };
    Ok(Json(
        publish_dynamic_capability_origin_local(&ccs_app, request).await?,
    ))
}

async fn resolve_dynamic_origin_internal_route(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    Json(request): Json<InternalDynamicResolveOriginRequest>,
) -> std::result::Result<Json<dynamic_caps::ControlDynamicResolveOriginResponse>, ProtocolApiError>
{
    authorize_local_controller_request(&app, &headers)?;
    Ok(Json(
        resolve_dynamic_capability_origin_internal(&app.control, request).await?,
    ))
}

async fn revoke_dynamic_origin_overlays(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    Json(request): Json<RevokeDynamicCapabilityOriginOverlaysRequest>,
) -> std::result::Result<StatusCode, ProtocolApiError> {
    authorize_local_controller_request(&app, &headers)?;
    revoke_dynamic_capability_origin_overlays_local(&app.control, &request)
        .await
        .map_err(ProtocolApiError::from)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn resolve_external_link_url(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    Json(request): Json<ResolveExternalLinkUrlRequest>,
) -> std::result::Result<Json<ResolveExternalLinkUrlResponse>, ProtocolApiError> {
    authorize_local_controller_request(&app, &headers)?;
    Ok(Json(
        resolve_external_link_url_local(&app.control, &request)
            .await
            .map_err(ProtocolApiError::from)?,
    ))
}

async fn publish_external_slot_overlay_route(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    Json(request): Json<PublishExternalSlotOverlayRequest>,
) -> std::result::Result<StatusCode, ProtocolApiError> {
    authorize_local_controller_request(&app, &headers)?;
    publish_external_slot_overlay_local(&app.control, &request)
        .await
        .map_err(ProtocolApiError::from)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn clear_external_slot_overlay_route(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    Json(request): Json<ClearExternalSlotOverlayRequest>,
) -> std::result::Result<StatusCode, ProtocolApiError> {
    authorize_local_controller_request(&app, &headers)?;
    clear_external_slot_overlay_local(&app.control, &request)
        .await
        .map_err(ProtocolApiError::from)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn publish_export_peer_overlay_route(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    Json(request): Json<PublishExportPeerOverlayRequest>,
) -> std::result::Result<StatusCode, ProtocolApiError> {
    authorize_local_controller_request(&app, &headers)?;
    publish_export_peer_overlay_local(&app.control, &request)
        .await
        .map_err(ProtocolApiError::from)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn clear_export_peer_overlay_route(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    Json(request): Json<ClearExportPeerOverlayRequest>,
) -> std::result::Result<StatusCode, ProtocolApiError> {
    authorize_local_controller_request(&app, &headers)?;
    clear_export_peer_overlay_local(&app.control, &request)
        .await
        .map_err(ProtocolApiError::from)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn control_dynamic_held_list_route(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    Json(request): Json<ControlDynamicHeldListRequest>,
) -> std::result::Result<Json<HeldListResponse>, ProtocolApiError> {
    authorize_framework_auth_header(&headers, app.control.control_state_auth_token.as_ref())?;
    match execute_site_controller_dynamic_caps_inspect(
        &app,
        DynamicCapsInspectRequest::HeldList(request),
        controller_local_only(&headers),
    )
    .await?
    {
        DynamicCapsInspectResponse::HeldList(response) => Ok(Json(response)),
        _ => unreachable!("held_list should return held list"),
    }
}

async fn control_dynamic_held_detail_route(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    Json(request): Json<ControlDynamicHeldDetailRequest>,
) -> std::result::Result<Json<HeldEntryDetail>, ProtocolApiError> {
    authorize_framework_auth_header(&headers, app.control.control_state_auth_token.as_ref())?;
    match execute_site_controller_dynamic_caps_inspect(
        &app,
        DynamicCapsInspectRequest::HeldDetail(request),
        controller_local_only(&headers),
    )
    .await?
    {
        DynamicCapsInspectResponse::HeldDetail(response) => Ok(Json(response)),
        _ => unreachable!("held_detail should return held detail"),
    }
}

async fn control_dynamic_share_route(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    Json(request): Json<ControlDynamicShareRequest>,
) -> std::result::Result<Json<amber_mesh::dynamic_caps::ShareResponse>, ProtocolApiError> {
    authorize_framework_auth_header(&headers, app.control.control_state_auth_token.as_ref())?;
    match execute_site_controller_dynamic_caps_mutate(
        &app,
        DynamicCapsMutateRequest::Share(request),
        controller_local_only(&headers),
    )
    .await?
    {
        DynamicCapsMutateResponse::Share(response) => Ok(Json(response)),
        _ => unreachable!("share should return share response"),
    }
}

async fn control_dynamic_inspect_ref_route(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    Json(request): Json<ControlDynamicInspectRefRequest>,
) -> std::result::Result<Json<amber_mesh::dynamic_caps::InspectRefResponse>, ProtocolApiError> {
    authorize_framework_auth_header(&headers, app.control.control_state_auth_token.as_ref())?;
    match execute_site_controller_dynamic_caps_inspect(
        &app,
        DynamicCapsInspectRequest::InspectRef(request),
        controller_local_only(&headers),
    )
    .await?
    {
        DynamicCapsInspectResponse::InspectRef(response) => Ok(Json(response)),
        _ => unreachable!("inspect_ref should return inspect response"),
    }
}

async fn control_dynamic_revoke_route(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    Json(request): Json<ControlDynamicRevokeRequest>,
) -> std::result::Result<Json<amber_mesh::dynamic_caps::RevokeResponse>, ProtocolApiError> {
    authorize_framework_auth_header(&headers, app.control.control_state_auth_token.as_ref())?;
    match execute_site_controller_dynamic_caps_mutate(
        &app,
        DynamicCapsMutateRequest::Revoke(request),
        controller_local_only(&headers),
    )
    .await?
    {
        DynamicCapsMutateResponse::Revoke(response) => Ok(Json(response)),
        _ => unreachable!("revoke should return revoke response"),
    }
}

async fn control_dynamic_resolve_origin_route(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    Json(request): Json<ControlDynamicResolveOriginRequest>,
) -> std::result::Result<Json<dynamic_caps::ControlDynamicResolveOriginResponse>, ProtocolApiError>
{
    authorize_framework_auth_header(&headers, app.control.control_state_auth_token.as_ref())?;
    match execute_site_controller_dynamic_caps_inspect(
        &app,
        DynamicCapsInspectRequest::ResolveOrigin(request),
        controller_local_only(&headers),
    )
    .await?
    {
        DynamicCapsInspectResponse::ResolveOrigin(response) => Ok(Json(response)),
        _ => unreachable!("resolve_origin should return origin resolution"),
    }
}
