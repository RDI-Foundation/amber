use std::sync::Arc;

use amber_mesh::dynamic_caps::HeldListResponse;
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
        DynamicCapsMutateResponse, resolve_dynamic_capability_origin_internal,
    },
    dynamic_caps::{
        self, ControlDynamicGrantAuthoritySyncRequest, ControlDynamicGrantAuthoritySyncResponse,
        ControlDynamicHeldDetailRequest, ControlDynamicHeldListRequest,
        ControlDynamicInspectRefRequest, ControlDynamicResolveOriginRequest,
        ControlDynamicResolveRefRequest, ControlDynamicRevokeRequest, ControlDynamicShareRequest,
        InternalDynamicResolveOriginRequest,
    },
    http::{
        cleanup_dynamic_bridge_proxies, post_json_with_retry, read_json, required_header,
        shutdown_signal,
    },
    orchestration::{
        ClearExportPeerOverlayRequest, ClearExternalSlotOverlayRequest, ProtocolApiError,
        PublishExportPeerOverlayRequest, PublishExternalSlotOverlayRequest,
        RemoteChildRollbackRequest, RemoteChildRuntimeRequest, ResolveExternalLinkUrlRequest,
        ResolveExternalLinkUrlResponse, RevokeDynamicCapabilityOriginOverlaysRequest,
        RouterIdentityRequest, RouterIdentityResponse, clear_export_peer_overlay_local,
        clear_external_slot_overlay_local, destroy_child_on_local_site, execute_create_child,
        execute_destroy_child, local_router_identity_for_overlay_site, prepare_child_on_local_site,
        publish_child_on_local_site, publish_dynamic_capability_origin_local,
        publish_export_peer_overlay_local, publish_external_slot_overlay_local,
        recover_control_state, resolve_external_link_url_local,
        revoke_dynamic_capability_origin_overlays_local, rollback_child_on_site,
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
    if let Some(identity_path) = plan.controller_identity_path.as_deref() {
        control_state.controller_identity = Some(read_json(
            Path::new(identity_path),
            "site controller mesh identity",
        )?);
    }
    persist_control_state(Path::new(&plan.state_path), &mut control_state)?;
    let control = ControlStateApp {
        control_state: Arc::new(Mutex::new(control_state)),
        client: ReqwestClient::new(),
        state_path: PathBuf::from(&plan.state_path),
        run_root: PathBuf::from(&plan.run_root),
        state_root: PathBuf::from(&plan.state_root),
        mesh_scope: Arc::<str>::from(plan.mesh_scope.clone()),
        control_state_auth_token: Arc::<str>::from(plan.control_state_auth_token.clone()),
        controller_plan: Arc::new(plan.clone()),
        authority_locks: Arc::new(Mutex::new(BTreeMap::new())),
        runtime,
    };
    let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let app_state = SiteControllerApp {
        control: control.clone(),
        ready: ready.clone(),
    };
    let app = site_controller_router(app_state.clone());
    let listener = TcpListener::bind(plan.listen_addr)
        .await
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to bind site controller on {}", plan.listen_addr))?;
    let serve_task = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(shutdown_signal())
            .await
            .into_diagnostic()
    });
    if let Err(err) = recover_control_state(&control).await {
        serve_task.abort();
        let _ = serve_task.await;
        let cleanup_result = cleanup_dynamic_bridge_proxies(&control).await;
        return match cleanup_result {
            Ok(()) => Err(err).wrap_err("site controller recovery failed"),
            Err(cleanup_err) => Err(miette::miette!(
                "site controller recovery failed: {err}\nbridge proxy cleanup failed: \
                 {cleanup_err}"
            )),
        };
    }
    ready.store(true, std::sync::atomic::Ordering::SeqCst);
    let serve_result = serve_task
        .await
        .into_diagnostic()
        .wrap_err("site controller task failed")?;
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
        .route("/", get(controller_healthz))
        .route("/healthz", get(controller_healthz))
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
            "/v1/internal/router-identity",
            post(get_internal_router_identity_route),
        )
        .route(
            "/v1/internal/children/prepare",
            post(prepare_child_runtime_route),
        )
        .route(
            "/v1/internal/children/publish",
            post(publish_child_runtime_route),
        )
        .route(
            "/v1/internal/children/rollback",
            post(rollback_child_runtime_route),
        )
        .route(
            "/v1/internal/children/destroy",
            post(destroy_child_runtime_route),
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
            "/v1/controller/dynamic-caps/grant-authorities/sync",
            post(control_dynamic_grant_authorities_sync_route),
        )
        .route(
            "/v1/controller/dynamic-caps/inspect-ref",
            post(control_dynamic_inspect_ref_route),
        )
        .route(
            "/v1/controller/dynamic-caps/resolve-ref",
            post(control_dynamic_resolve_ref_route),
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

async fn controller_healthz(State(app): State<SiteControllerApp>) -> Response {
    let ready = app.ready.load(std::sync::atomic::Ordering::SeqCst);
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(json!({ "ok": ready }))).into_response()
}

async fn get_site_controller_state_route(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
) -> std::result::Result<Json<FrameworkControlState>, ProtocolApiError> {
    authorize_local_controller_request(&app, &headers).await?;
    Ok(Json(app.control.control_state.lock().await.clone()))
}

fn controller_local_only(headers: &HeaderMap) -> bool {
    headers
        .get(CONTROLLER_LOCAL_ONLY_HEADER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == "1")
}

pub(super) async fn authorize_local_controller_request(
    app: &SiteControllerApp,
    headers: &HeaderMap,
) -> std::result::Result<(), ProtocolApiError> {
    if !controller_local_only(headers) {
        return Err(ProtocolApiError::unauthorized(
            "local controller endpoint requires router-local forwarding".to_string(),
        ));
    }
    let route_id = required_header(headers, FRAMEWORK_ROUTE_ID_HEADER)?;
    let expected_route_id = {
        let state = app.control.control_state.lock().await;
        let scenario = amber_scenario::Scenario::try_from(state.base_scenario.clone()).map_err(
            |err| {
                ProtocolApiError::control_state_unavailable(format!(
                    "failed to read lowered scenario while authorizing a local controller                      request: {err}"
                ))
            },
        )?;
        let controller_peer_id = scenario
            .components_iter()
            .find(|(_, component)| {
                amber_compiler::run_plan::framework_component_controller_metadata(
                    component.metadata.as_ref(),
                )
                .is_some_and(|metadata| {
                    metadata.execution_site == app.control.controller_plan.site_id
                })
            })
            .map(|(_, component)| component.moniker.as_str().to_string())
            .ok_or_else(|| {
                ProtocolApiError::control_state_unavailable(format!(
                    "site controller component for site `{}` is missing from the lowered scenario",
                    app.control.controller_plan.site_id,
                ))
            })?;
        amber_mesh::component_route_id(
            controller_peer_id.as_str(),
            amber_mesh::FRAMEWORK_COMPONENT_CONTROLLER_INTERNAL_PROVIDE_NAME,
            amber_mesh::MeshProtocol::Http,
        )
    };
    if route_id != expected_route_id {
        return Err(ProtocolApiError::unauthorized(format!(
            "local controller endpoint requires internal route `{expected_route_id}`"
        )));
    }
    let peer_id = required_header(headers, FRAMEWORK_PEER_ID_HEADER)?;
    let local_router_id = app.control.controller_plan.router_identity_id.as_str();
    let known_peer_router = app
        .control
        .controller_plan
        .peer_router_identities
        .values()
        .any(|identity| identity.id == peer_id);
    if peer_id != local_router_id && !known_peer_router {
        return Err(ProtocolApiError::unauthorized(format!(
            "local controller endpoint received an unknown router peer `{peer_id}`"
        )));
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
    authorize_remote_controller_request(&app, &headers).await?;
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

async fn get_internal_router_identity_route(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    Json(request): Json<RouterIdentityRequest>,
) -> std::result::Result<Json<RouterIdentityResponse>, ProtocolApiError> {
    authorize_remote_controller_request(&app, &headers).await?;
    let execution_site = {
        let state = app.control.control_state.lock().await;
        super::orchestration::site_execution_site_from_state(&state, &request.site_id)?.to_string()
    };
    if execution_site != app.control.controller_plan.site_id {
        return Err(ProtocolApiError::control_state_unavailable(format!(
            "site `{}` is controlled by `{execution_site}`, not `{}`",
            request.site_id, app.control.controller_plan.site_id,
        )));
    }
    let identity = local_router_identity_for_overlay_site(&app.control, &request.site_id).await?;
    Ok(Json(RouterIdentityResponse {
        id: identity.id,
        public_key_b64: base64::engine::general_purpose::STANDARD.encode(identity.public_key),
    }))
}

pub(super) async fn authorize_public_request(
    app: &SiteControllerApp,
    headers: &HeaderMap,
) -> std::result::Result<(CapabilityInstanceRecord, FrameworkControlState), ProtocolApiError> {
    let route_id = required_header(headers, FRAMEWORK_ROUTE_ID_HEADER)?;
    let peer_id = required_header(headers, FRAMEWORK_PEER_ID_HEADER)?;
    let state = app.control.control_state.lock().await.clone();
    let record = super::api::authorize_capability_route(&state, &route_id, &peer_id)
        .map_err(ProtocolApiError::from)?
        .clone();
    Ok((record, state))
}

pub(super) async fn authorize_remote_controller_request(
    app: &SiteControllerApp,
    headers: &HeaderMap,
) -> std::result::Result<(), ProtocolApiError> {
    let (record, state) = authorize_public_request(app, headers).await?;
    if record.capability != amber_mesh::FRAMEWORK_COMPONENT_CONTROLLER_INTERNAL_PROVIDE_NAME {
        return Err(ProtocolApiError::unauthorized(
            "remote site controller requests must arrive over the ordinary controller internal \
             capability"
                .to_string(),
        ));
    }
    let is_controller = state
        .base_scenario
        .components
        .iter()
        .find(|component| component.id == record.recipient_component_id)
        .is_some_and(|component| {
            amber_compiler::run_plan::framework_component_controller_metadata(
                component.metadata.as_ref(),
            )
            .is_some()
        });
    if !is_controller {
        return Err(ProtocolApiError::unauthorized(
            "remote site controller requests must target a synthetic controller component"
                .to_string(),
        ));
    }
    Ok(())
}
pub(super) fn authorize_dynamic_caps_sidecar_request(
    headers: &HeaderMap,
    expected_component_id: &str,
) -> std::result::Result<(), ProtocolApiError> {
    let route_id = required_header(headers, FRAMEWORK_ROUTE_ID_HEADER)?;
    if !route_id.ends_with(&format!(
        ":{}:http",
        amber_mesh::FRAMEWORK_COMPONENT_CONTROLLER_INTERNAL_PROVIDE_NAME
    )) {
        return Err(ProtocolApiError::unauthorized(
            "dynamic capability control requests must arrive over the site controller internal \
             route"
                .to_string(),
        ));
    }
    let peer_id = required_header(headers, FRAMEWORK_PEER_ID_HEADER)?;
    let expected_peer_id = dynamic_caps::moniker_from_logical_component_id(expected_component_id)
        .map_err(ProtocolApiError::from)?;
    if peer_id != expected_peer_id {
        return Err(ProtocolApiError::unauthorized(format!(
            "dynamic capability control request for `{expected_component_id}` came from \
             `{peer_id}`"
        )));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DynamicCapsRequestAuth {
    Sidecar,
    RemoteController,
}

pub(super) async fn authorize_dynamic_caps_request(
    app: &SiteControllerApp,
    headers: &HeaderMap,
    expected_component_id: &str,
) -> std::result::Result<DynamicCapsRequestAuth, ProtocolApiError> {
    let peer_id = required_header(headers, FRAMEWORK_PEER_ID_HEADER)?;
    let expected_sidecar_peer =
        dynamic_caps::moniker_from_logical_component_id(expected_component_id)
            .map_err(ProtocolApiError::from)?;
    if peer_id == expected_sidecar_peer {
        authorize_dynamic_caps_sidecar_request(headers, expected_component_id)?;
        return Ok(DynamicCapsRequestAuth::Sidecar);
    }
    authorize_remote_controller_request(app, headers).await?;
    Ok(DynamicCapsRequestAuth::RemoteController)
}

fn ensure_controller_ready(app: &SiteControllerApp) -> std::result::Result<(), ProtocolApiError> {
    if app.ready.load(std::sync::atomic::Ordering::SeqCst) {
        return Ok(());
    }
    Err(ProtocolApiError::control_state_unavailable(
        "site controller is still recovering",
    ))
}

fn remote_controller_urls(app: &SiteControllerApp) -> BTreeMap<String, String> {
    app.control
        .controller_plan
        .peer_site_router_urls
        .iter()
        .filter(|(site_id, _)| site_id.as_str() != app.control.controller_plan.site_id)
        .map(|(site_id, url)| (site_id.clone(), url.clone()))
        .collect()
}

fn remote_controller_base_url(
    app: &SiteControllerApp,
    site_id: &str,
) -> std::result::Result<String, ProtocolApiError> {
    remote_controller_urls(app).remove(site_id).ok_or_else(|| {
        ProtocolApiError::control_state_unavailable(format!(
            "site controller `{}` has no router-local controller route to site `{site_id}`",
            app.control.controller_plan.site_id
        ))
    })
}

async fn remote_controller_post<TReq: Serialize, TResp: DeserializeOwned>(
    app: &SiteControllerApp,
    site_id: &str,
    path: &str,
    body: &TReq,
) -> std::result::Result<TResp, ProtocolApiError> {
    let url = format!(
        "{}{}",
        remote_controller_base_url(app, site_id)?.trim_end_matches('/'),
        path
    );
    let response = post_json_with_retry(&app.control.client, &url, body)
        .await
        .map_err(|err| {
            ProtocolApiError::control_state_unavailable(format!(
                "failed to reach site controller for site `{site_id}` through its router-local \
                 controller route: {err}"
            ))
        })?;
    if response.status().is_success() {
        return response.json().await.map_err(|err| {
            ProtocolApiError::control_state_unavailable(format!(
                "site controller for site `{site_id}` returned invalid JSON through its \
                 router-local controller route: {err}"
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
        "site controller for site `{site_id}` returned {status} through its router-local \
         controller route"
    )))
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

pub(super) async fn execute_site_controller_dynamic_caps_resolve_ref(
    app: &SiteControllerApp,
    request: ControlDynamicResolveRefRequest,
) -> std::result::Result<dynamic_caps::ControlDynamicResolveRefResponse, ProtocolApiError> {
    let inspected = match execute_site_controller_dynamic_caps_inspect(
        app,
        DynamicCapsInspectRequest::InspectRef(ControlDynamicInspectRefRequest {
            holder_component_id: request.holder_component_id.clone(),
            r#ref: request.r#ref.clone(),
        }),
        false,
    )
    .await?
    {
        DynamicCapsInspectResponse::InspectRef(response) => response,
        _ => unreachable!("inspect_ref should return inspect response"),
    };
    let origin = match execute_site_controller_dynamic_caps_inspect(
        app,
        DynamicCapsInspectRequest::ResolveOrigin(ControlDynamicResolveOriginRequest {
            holder_component_id: request.holder_component_id,
            source: dynamic_caps::DynamicCapabilityControlSourceRequest::Grant {
                grant_id: inspected.grant_id.clone(),
            },
        }),
        false,
    )
    .await?
    {
        DynamicCapsInspectResponse::ResolveOrigin(response) => response,
        _ => unreachable!("resolve_origin should return origin resolution"),
    };
    let parsed = amber_mesh::dynamic_caps::decode_dynamic_capability_ref_unverified(&request.r#ref)
        .map_err(|err| {
            ProtocolApiError::from(protocol_error(
                ProtocolErrorCode::MalformedRef,
                &format!("dynamic capability ref is malformed: {err}"),
            ))
        })?;
    Ok(dynamic_caps::ControlDynamicResolveRefResponse {
        origin,
        relative_path: parsed.relative_path,
        query: parsed.query,
        fragment: parsed.fragment,
    })
}

async fn local_share(
    app: &SiteControllerApp,
    request: ControlDynamicShareRequest,
) -> std::result::Result<amber_mesh::dynamic_caps::ShareResponse, ProtocolApiError> {
    let response = match control_state_api::execute_dynamic_caps_mutate(
        &app.control,
        DynamicCapsMutateRequest::Share(request.clone()),
    )
    .await?
    {
        DynamicCapsMutateResponse::Share(response) => response,
        _ => unreachable!("share should return share response"),
    };
    if let Err(err) = sync_shared_grant_authority_site(app, &response).await {
        if response.outcome == "created"
            && let Some(grant_id) = response.grant_id.as_ref()
            && let Err(rollback_err) = control_state_api::execute_dynamic_caps_mutate(
                &app.control,
                DynamicCapsMutateRequest::Revoke(ControlDynamicRevokeRequest {
                    caller_component_id: request.caller_component_id,
                    target: dynamic_caps::DynamicCapabilityControlSourceRequest::Grant {
                        grant_id: grant_id.clone(),
                    },
                }),
            )
            .await
        {
            return Err(ProtocolApiError::control_state_unavailable(format!(
                "{}; failed to roll back shared grant `{grant_id}` after sync failure: {}",
                err.0.message, rollback_err.0.message
            )));
        }
        return Err(err);
    }
    Ok(response)
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

async fn sync_shared_grant_authority_site(
    app: &SiteControllerApp,
    response: &amber_mesh::dynamic_caps::ShareResponse,
) -> std::result::Result<(), ProtocolApiError> {
    let Some(grant_id) = response.grant_id.as_ref() else {
        return Ok(());
    };
    let holder_site_id = {
        let state = app.control.control_state.lock().await;
        let grant = state
            .dynamic_capability_grants
            .get(grant_id)
            .ok_or_else(|| {
                ProtocolApiError::control_state_unavailable(format!(
                        "dynamic capability share reported grant `{grant_id}` but it is missing \
                         from                      site controller `{}` state",
                        app.control.controller_plan.site_id
                    ))
            })?;
        site_id_for_logical_component(&state, &grant.holder_component_id).map_err(|err| {
            ProtocolApiError::control_state_unavailable(format!(
                "shared grant `{grant_id}` holder `{}` has no live site assignment: {}",
                grant.holder_component_id, err.message
            ))
        })?
    };
    let authority_site_id = app.control.controller_plan.site_id.as_str();
    if holder_site_id == authority_site_id {
        return Ok(());
    }
    let _: ControlDynamicGrantAuthoritySyncResponse = remote_controller_post(
        app,
        &holder_site_id,
        "/v1/controller/dynamic-caps/grant-authorities/sync",
        &ControlDynamicGrantAuthoritySyncRequest {
            authority_sites: BTreeMap::from([(grant_id.clone(), authority_site_id.to_string())]),
        },
    )
    .await?;
    Ok(())
}

async fn local_sync_dynamic_grant_authorities(
    app: &SiteControllerApp,
    request: ControlDynamicGrantAuthoritySyncRequest,
) -> std::result::Result<ControlDynamicGrantAuthoritySyncResponse, ProtocolApiError> {
    let synced = request.authority_sites.len();
    {
        let mut state = app.control.control_state.lock().await;
        persist_control_state_update(
            &mut state,
            &app.control.state_path,
            "dynamic capability grant authority sync",
            |state| {
                dynamic_caps::sync_dynamic_capability_grant_authority_sites(
                    state,
                    &request.authority_sites,
                );
                Ok(())
            },
        )?;
    }
    Ok(ControlDynamicGrantAuthoritySyncResponse { synced })
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
    _state: &FrameworkControlState,
    record: &CapabilityInstanceRecord,
) -> std::result::Result<String, ProtocolApiError> {
    if !record.controller_site_id.is_empty() {
        return Ok(record.controller_site_id.clone());
    }
    Err(ProtocolApiError::from(protocol_error(
        ProtocolErrorCode::ControlStateUnavailable,
        &format!(
            "framework.component capability instance `{}` is missing its controller_site_id",
            record.cap_instance_id
        ),
    )))
}

pub(super) async fn execute_site_controller_framework_inspect(
    app: &SiteControllerApp,
    record: &CapabilityInstanceRecord,
    state: &FrameworkControlState,
    request: FrameworkComponentInspectRequest,
) -> std::result::Result<FrameworkComponentInspectResponse, ProtocolApiError> {
    ensure_controller_ready(app)?;
    let authority_site = framework_request_site_id(state, record)?;
    if authority_site != app.control.controller_plan.site_id {
        return Err(ProtocolApiError::control_state_unavailable(format!(
            "framework.component request is bound to controller site `{authority_site}` but \
             reached site controller `{}`",
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
    ensure_controller_ready(app)?;
    let authority_site = framework_request_site_id(state, record)?;
    if authority_site != app.control.controller_plan.site_id {
        return Err(ProtocolApiError::control_state_unavailable(format!(
            "framework.component request is bound to controller site `{authority_site}` but \
             reached site controller `{}`",
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
    ensure_controller_ready(app)?;
    match request {
        DynamicCapsInspectRequest::HeldList(request) => {
            if local_only {
                return Ok(DynamicCapsInspectResponse::HeldList(
                    local_held_list(app, request).await?,
                ));
            }
            let mut held = local_held_list(app, request.clone()).await?.held;
            for site_id in remote_controller_urls(app).into_keys() {
                held.extend(
                    remote_controller_post::<_, HeldListResponse>(
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
            held.dedup_by(|left, right| left.held_id == right.held_id);
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
                remote_controller_post(
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
                remote_controller_post(
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
            let holder_peer = control_state_api::local_component_runtime(
                &app.control,
                &state,
                &request.holder_component_id,
            )?
            .mesh_config
            .identity;
            Ok(DynamicCapsInspectResponse::ResolveOrigin(
                remote_controller_post(
                    app,
                    &site_id,
                    "/v1/internal/dynamic-caps/resolve-origin",
                    &InternalDynamicResolveOriginRequest {
                        holder_component_id: request.holder_component_id,
                        source: request.source,
                        holder_peer_id: holder_peer.id,
                        holder_peer_key_b64: base64::engine::general_purpose::STANDARD
                            .encode(holder_peer.public_key),
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
    ensure_controller_ready(app)?;
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
                remote_controller_post(
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
                remote_controller_post(
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
    authorize_remote_controller_request(&app, &headers).await?;
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
    authorize_remote_controller_request(&app, &headers).await?;
    Ok(Json(
        resolve_dynamic_capability_origin_internal(&app.control, request).await?,
    ))
}

async fn revoke_dynamic_origin_overlays(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    Json(request): Json<RevokeDynamicCapabilityOriginOverlaysRequest>,
) -> std::result::Result<StatusCode, ProtocolApiError> {
    authorize_remote_controller_request(&app, &headers).await?;
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
    authorize_remote_controller_request(&app, &headers).await?;
    Ok(Json(
        resolve_external_link_url_local(&app.control, &request)
            .await
            .map_err(ProtocolApiError::from)?,
    ))
}

async fn prepare_child_runtime_route(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    Json(request): Json<RemoteChildRuntimeRequest>,
) -> std::result::Result<StatusCode, ProtocolApiError> {
    authorize_remote_controller_request(&app, &headers).await?;
    ensure_controller_ready(&app)?;
    prepare_child_on_local_site(
        &app.control,
        &request.state,
        &request.child,
        &request.site_id,
    )
    .await
    .map_err(ProtocolApiError::from)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn publish_child_runtime_route(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    Json(request): Json<RemoteChildRuntimeRequest>,
) -> std::result::Result<StatusCode, ProtocolApiError> {
    authorize_remote_controller_request(&app, &headers).await?;
    ensure_controller_ready(&app)?;
    publish_child_on_local_site(
        &app.control,
        &request.state,
        &request.child,
        &request.site_id,
    )
    .await
    .map_err(ProtocolApiError::from)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn rollback_child_runtime_route(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    Json(request): Json<RemoteChildRollbackRequest>,
) -> std::result::Result<StatusCode, ProtocolApiError> {
    authorize_remote_controller_request(&app, &headers).await?;
    ensure_controller_ready(&app)?;
    rollback_child_on_site(&app.control, request.child_id, &request.site_id)
        .await
        .map_err(|err| ProtocolApiError::control_state_unavailable(err.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn destroy_child_runtime_route(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    Json(request): Json<RemoteChildRuntimeRequest>,
) -> std::result::Result<StatusCode, ProtocolApiError> {
    authorize_remote_controller_request(&app, &headers).await?;
    ensure_controller_ready(&app)?;
    destroy_child_on_local_site(
        &app.control,
        &request.state,
        &request.child,
        &request.site_id,
    )
    .await
    .map_err(ProtocolApiError::from)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn publish_external_slot_overlay_route(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    Json(request): Json<PublishExternalSlotOverlayRequest>,
) -> std::result::Result<StatusCode, ProtocolApiError> {
    authorize_remote_controller_request(&app, &headers).await?;
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
    authorize_remote_controller_request(&app, &headers).await?;
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
    authorize_remote_controller_request(&app, &headers).await?;
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
    authorize_remote_controller_request(&app, &headers).await?;
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
    let auth = authorize_dynamic_caps_request(&app, &headers, &request.holder_component_id).await?;
    match execute_site_controller_dynamic_caps_inspect(
        &app,
        DynamicCapsInspectRequest::HeldList(request),
        matches!(auth, DynamicCapsRequestAuth::RemoteController),
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
    let auth = authorize_dynamic_caps_request(&app, &headers, &request.holder_component_id).await?;
    match execute_site_controller_dynamic_caps_inspect(
        &app,
        DynamicCapsInspectRequest::HeldDetail(request),
        matches!(auth, DynamicCapsRequestAuth::RemoteController),
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
    let auth = authorize_dynamic_caps_request(&app, &headers, &request.caller_component_id).await?;
    match execute_site_controller_dynamic_caps_mutate(
        &app,
        DynamicCapsMutateRequest::Share(request),
        matches!(auth, DynamicCapsRequestAuth::RemoteController),
    )
    .await?
    {
        DynamicCapsMutateResponse::Share(response) => Ok(Json(response)),
        _ => unreachable!("share should return share response"),
    }
}

async fn control_dynamic_grant_authorities_sync_route(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    Json(request): Json<ControlDynamicGrantAuthoritySyncRequest>,
) -> std::result::Result<Json<ControlDynamicGrantAuthoritySyncResponse>, ProtocolApiError> {
    authorize_remote_controller_request(&app, &headers).await?;
    Ok(Json(
        local_sync_dynamic_grant_authorities(&app, request).await?,
    ))
}

async fn control_dynamic_inspect_ref_route(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    Json(request): Json<ControlDynamicInspectRefRequest>,
) -> std::result::Result<Json<amber_mesh::dynamic_caps::InspectRefResponse>, ProtocolApiError> {
    let auth = authorize_dynamic_caps_request(&app, &headers, &request.holder_component_id).await?;
    match execute_site_controller_dynamic_caps_inspect(
        &app,
        DynamicCapsInspectRequest::InspectRef(request),
        matches!(auth, DynamicCapsRequestAuth::RemoteController),
    )
    .await?
    {
        DynamicCapsInspectResponse::InspectRef(response) => Ok(Json(response)),
        _ => unreachable!("inspect_ref should return inspect response"),
    }
}

async fn control_dynamic_resolve_ref_route(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    Json(request): Json<ControlDynamicResolveRefRequest>,
) -> std::result::Result<Json<dynamic_caps::ControlDynamicResolveRefResponse>, ProtocolApiError> {
    let auth = authorize_dynamic_caps_request(&app, &headers, &request.holder_component_id).await?;
    if auth != DynamicCapsRequestAuth::Sidecar {
        return Err(ProtocolApiError::unauthorized(
            "dynamic capability ref resolution must be requested by the holder component sidecar"
                .to_string(),
        ));
    }
    Ok(Json(
        execute_site_controller_dynamic_caps_resolve_ref(&app, request).await?,
    ))
}

async fn control_dynamic_revoke_route(
    State(app): State<SiteControllerApp>,
    headers: HeaderMap,
    Json(request): Json<ControlDynamicRevokeRequest>,
) -> std::result::Result<Json<amber_mesh::dynamic_caps::RevokeResponse>, ProtocolApiError> {
    let auth = authorize_dynamic_caps_request(&app, &headers, &request.caller_component_id).await?;
    match execute_site_controller_dynamic_caps_mutate(
        &app,
        DynamicCapsMutateRequest::Revoke(request),
        matches!(auth, DynamicCapsRequestAuth::RemoteController),
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
    let auth = authorize_dynamic_caps_request(&app, &headers, &request.holder_component_id).await?;
    match execute_site_controller_dynamic_caps_inspect(
        &app,
        DynamicCapsInspectRequest::ResolveOrigin(request),
        matches!(auth, DynamicCapsRequestAuth::RemoteController),
    )
    .await?
    {
        DynamicCapsInspectResponse::ResolveOrigin(response) => Ok(Json(response)),
        _ => unreachable!("resolve_origin should return origin resolution"),
    }
}
