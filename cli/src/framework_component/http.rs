use super::{api::*, orchestration::*, planner::*, state::*, *};

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
        control_state_auth_token: Arc::<str>::from(plan.auth_token),
        authority_locks: Arc::new(Mutex::new(BTreeMap::new())),
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
        .route(
            "/v1/control-state/dynamic-caps/held",
            post(control_dynamic_held_list),
        )
        .route(
            "/v1/control-state/dynamic-caps/held/detail",
            post(control_dynamic_held_detail),
        )
        .route(
            "/v1/control-state/dynamic-caps/share",
            post(control_dynamic_share),
        )
        .route(
            "/v1/control-state/dynamic-caps/inspect-ref",
            post(control_dynamic_inspect_ref),
        )
        .route(
            "/v1/control-state/dynamic-caps/revoke",
            post(control_dynamic_revoke),
        )
        .route(
            "/v1/control-state/dynamic-caps/resolve-origin",
            post(control_dynamic_resolve_origin),
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
    let app_state = CcsApp {
        client: ReqwestClient::new(),
        site_state_root: PathBuf::from(&plan.site_state_root),
        control_state_url: Arc::<str>::from(plan.control_state_url),
        router_auth_token: Arc::<str>::from(plan.router_auth_token),
        control_state_auth_token: Arc::<str>::from(plan.control_state_auth_token),
    };
    let app = Router::new()
        .nest_service("/mcp", mcp::service(app_state.clone()))
        .route("/", get(healthz))
        .route("/healthz", get(healthz))
        .route("/v1/templates", get(ccs_list_templates))
        .route("/v1/templates/{template}", get(ccs_describe_template))
        .route(
            "/v1/templates/{template}/resolve",
            post(ccs_resolve_template),
        )
        .route(
            "/v1/children",
            get(ccs_list_children).post(ccs_create_child),
        )
        .route(
            "/v1/children/{child}",
            get(ccs_describe_child).delete(ccs_destroy_child),
        )
        .route("/v1/snapshot", post(ccs_snapshot))
        .route(
            "/v1/internal/dynamic-caps/origins/publish",
            post(ccs_publish_dynamic_capability_origin),
        )
        .with_state(app_state);
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

pub(super) async fn healthz() -> Json<serde_json::Value> {
    Json(json!({ "ok": true }))
}

pub(super) async fn cleanup_dynamic_bridge_proxies(app: &ControlStateApp) -> Result<()> {
    let mut bridge_proxies = {
        let mut guard = app.bridge_proxies.lock().await;
        std::mem::take(&mut *guard)
    };
    stop_bridge_proxies(&mut bridge_proxies).await
}

pub(super) async fn get_control_state(
    State(app): State<ControlStateApp>,
    headers: HeaderMap,
) -> std::result::Result<Json<FrameworkControlState>, ProtocolApiError> {
    authorize_framework_auth_header(&headers, app.control_state_auth_token.as_ref())?;
    Ok(Json(app.control_state.lock().await.clone()))
}

pub(super) async fn control_create_child(
    State(app): State<ControlStateApp>,
    headers: HeaderMap,
    Json(request): Json<ControlCreateChildRequest>,
) -> std::result::Result<Json<CreateChildResponse>, ProtocolApiError> {
    authorize_framework_auth_header(&headers, app.control_state_auth_token.as_ref())?;
    let authority_realm_id = {
        let state = app.control_state.lock().await;
        capability_instance_record(&state, &request.cap_instance_id)
            .map_err(ProtocolApiError::from)?
            .authority_realm_id
    };
    Ok(Json(
        execute_create_child(&app, authority_realm_id, request.request).await?,
    ))
}

pub(super) async fn control_destroy_child(
    State(app): State<ControlStateApp>,
    headers: HeaderMap,
    AxumPath(child): AxumPath<String>,
    Json(request): Json<ControlDestroyChildRequest>,
) -> std::result::Result<StatusCode, ProtocolApiError> {
    authorize_framework_auth_header(&headers, app.control_state_auth_token.as_ref())?;
    let authority_realm_id = {
        let state = app.control_state.lock().await;
        capability_instance_record(&state, &request.cap_instance_id)
            .map_err(ProtocolApiError::from)?
            .authority_realm_id
    };
    execute_destroy_child(&app, authority_realm_id, &child).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn control_dynamic_held_list(
    State(app): State<ControlStateApp>,
    headers: HeaderMap,
    Json(request): Json<dynamic_caps::ControlDynamicHeldListRequest>,
) -> std::result::Result<Json<amber_mesh::dynamic_caps::HeldListResponse>, ProtocolApiError> {
    authorize_framework_auth_header(&headers, app.control_state_auth_token.as_ref())?;
    let held = {
        let state = app.control_state.lock().await;
        dynamic_caps::live_held_entries(&state, &request.holder_component_id)?
    };
    Ok(Json(amber_mesh::dynamic_caps::HeldListResponse { held }))
}

pub(super) async fn control_dynamic_held_detail(
    State(app): State<ControlStateApp>,
    headers: HeaderMap,
    Json(request): Json<dynamic_caps::ControlDynamicHeldDetailRequest>,
) -> std::result::Result<Json<HeldEntryDetail>, ProtocolApiError> {
    authorize_framework_auth_header(&headers, app.control_state_auth_token.as_ref())?;
    let detail = {
        let state = app.control_state.lock().await;
        dynamic_caps::held_entry_detail(&state, &request.holder_component_id, &request.held_id)?
    };
    Ok(Json(detail))
}

pub(super) async fn control_dynamic_share(
    State(app): State<ControlStateApp>,
    headers: HeaderMap,
    Json(request): Json<dynamic_caps::ControlDynamicShareRequest>,
) -> std::result::Result<Json<amber_mesh::dynamic_caps::ShareResponse>, ProtocolApiError> {
    authorize_framework_auth_header(&headers, app.control_state_auth_token.as_ref())?;
    let response = {
        let mut state = app.control_state.lock().await;
        persist_control_state_update(
            &mut state,
            &app.state_path,
            "dynamic capability share",
            |state| {
                let outcome = dynamic_caps::share_dynamic_capability(
                    state,
                    &request.caller_component_id,
                    &dynamic_caps::source_key_from_control_request(&request.source),
                    &request.recipient_component_id,
                    request.idempotency_key.as_deref(),
                    &request.options,
                )?;
                Ok(match outcome {
                    dynamic_caps::DynamicCapabilityShareOutcome::Created { grant_id, r#ref } => {
                        amber_mesh::dynamic_caps::ShareResponse {
                            outcome: "created".to_string(),
                            reason: None,
                            grant_id: Some(grant_id),
                            r#ref: Some(r#ref),
                        }
                    }
                    dynamic_caps::DynamicCapabilityShareOutcome::Deduplicated {
                        grant_id,
                        r#ref,
                    } => amber_mesh::dynamic_caps::ShareResponse {
                        outcome: "deduplicated".to_string(),
                        reason: None,
                        grant_id: Some(grant_id),
                        r#ref: Some(r#ref),
                    },
                    dynamic_caps::DynamicCapabilityShareOutcome::Noop { reason } => {
                        amber_mesh::dynamic_caps::ShareResponse {
                            outcome: "noop".to_string(),
                            reason: Some(reason),
                            grant_id: None,
                            r#ref: None,
                        }
                    }
                })
            },
        )?
    };
    Ok(Json(response))
}

pub(super) async fn control_dynamic_inspect_ref(
    State(app): State<ControlStateApp>,
    headers: HeaderMap,
    Json(request): Json<dynamic_caps::ControlDynamicInspectRefRequest>,
) -> std::result::Result<Json<amber_mesh::dynamic_caps::InspectRefResponse>, ProtocolApiError> {
    authorize_framework_auth_header(&headers, app.control_state_auth_token.as_ref())?;
    let response = {
        let state = app.control_state.lock().await;
        dynamic_caps::inspect_dynamic_ref(&state, &request.holder_component_id, &request.r#ref)?
    };
    Ok(Json(response))
}

pub(super) async fn control_dynamic_revoke(
    State(app): State<ControlStateApp>,
    headers: HeaderMap,
    Json(request): Json<dynamic_caps::ControlDynamicRevokeRequest>,
) -> std::result::Result<Json<amber_mesh::dynamic_caps::RevokeResponse>, ProtocolApiError> {
    authorize_framework_auth_header(&headers, app.control_state_auth_token.as_ref())?;
    {
        let mut state = app.control_state.lock().await;
        persist_control_state_update(
            &mut state,
            &app.state_path,
            "dynamic capability revoke",
            |state| {
                dynamic_caps::revoke_dynamic_capability(
                    state,
                    &request.caller_component_id,
                    &dynamic_caps::source_key_from_control_request(&request.target),
                )?;
                Ok(())
            },
        )?;
    }
    Ok(Json(amber_mesh::dynamic_caps::RevokeResponse {
        outcome: "revoked".to_string(),
    }))
}

pub(super) async fn control_dynamic_resolve_origin(
    State(app): State<ControlStateApp>,
    headers: HeaderMap,
    Json(request): Json<dynamic_caps::ControlDynamicResolveOriginRequest>,
) -> std::result::Result<Json<dynamic_caps::ControlDynamicResolveOriginResponse>, ProtocolApiError>
{
    authorize_framework_auth_header(&headers, app.control_state_auth_token.as_ref())?;
    let state = app.control_state.lock().await.clone();
    let source_key = dynamic_caps::source_key_from_control_request(&request.source);
    let resolved_source = dynamic_caps::resolve_dynamic_materialization_source(
        &state,
        &request.holder_component_id,
        &source_key,
    )?;
    let roots = dynamic_caps::derive_root_authorities(&state)?;
    let root = roots
        .get(&dynamic_caps::root_authority_key(
            &resolved_source.root_authority_selector,
        ))
        .ok_or_else(|| {
            ProtocolApiError::from(protocol_error(
                ProtocolErrorCode::OriginUnavailable,
                "dynamic capability root authority is no longer live",
            ))
        })?;
    let holder_runtime =
        dynamic_capability_component_runtime_endpoint(&app, &state, &request.holder_component_id)?;
    let holder_plan = load_site_actuator_plan(&app, &holder_runtime.site_id)?;
    let origin_runtime =
        dynamic_capability_component_runtime_endpoint(&app, &state, &root.holder_component_id)?;
    let origin_site_id = origin_runtime.site_id.clone();
    let origin_plan = load_site_actuator_plan(&app, &origin_site_id)?;
    let origin_manager_state = load_site_manager_state(&app, &origin_site_id)?;
    let origin_peer_id = origin_manager_state
        .router_identity_id
        .clone()
        .ok_or_else(|| {
            ProtocolApiError::from(protocol_error(
                ProtocolErrorCode::OriginUnavailable,
                &format!(
                    "site `{origin_site_id}` does not expose a live router identity for dynamic \
                     capability publication"
                ),
            ))
        })?;
    let origin_peer_key_b64 = origin_manager_state
        .router_public_key_b64
        .clone()
        .ok_or_else(|| {
            ProtocolApiError::from(protocol_error(
                ProtocolErrorCode::OriginUnavailable,
                &format!(
                    "site `{origin_site_id}` does not expose a live router public key for dynamic \
                     capability publication"
                ),
            ))
        })?;
    let origin_peer_addr = origin_manager_state
        .router_mesh_addr
        .as_deref()
        .ok_or_else(|| {
            ProtocolApiError::from(protocol_error(
                ProtocolErrorCode::OriginUnavailable,
                &format!(
                    "site `{origin_site_id}` does not expose a live router mesh address for \
                     dynamic capability publication"
                ),
            ))
        })
        .and_then(|router_mesh_addr| {
            router_mesh_addr_for_consumer(origin_plan.kind, holder_plan.kind, router_mesh_addr)
                .map_err(|err| {
                    ProtocolApiError::from(protocol_error(
                        ProtocolErrorCode::OriginUnavailable,
                        &format!(
                            "site `{origin_site_id}` exposes an invalid live router mesh address \
                             for dynamic capability publication: {err}"
                        ),
                    ))
                })
        })?;
    let overlay_suffix = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "holder_component_id": request.holder_component_id,
            "root_authority_selector": resolved_source.root_authority_selector.clone(),
        }))
        .expect("dynamic capability origin overlay key should serialize"),
    );
    let overlay_id = format!("dynamic-cap-origin-{overlay_suffix}");
    let route_id = format!("dynamic-cap-origin-route-{overlay_suffix}");
    let publish = publish_dynamic_capability_origin(
        &app,
        &origin_site_id,
        &dynamic_caps::PublishDynamicCapabilityOriginRequest {
            overlay_id,
            route_id: route_id.clone(),
            root_authority_selector: resolved_source.root_authority_selector.clone(),
            allowed_peers: vec![dynamic_caps::DynamicCapabilityAllowedPeer {
                peer_id: holder_runtime.runtime.mesh_config.identity.id.clone(),
                peer_key_b64: base64::engine::general_purpose::STANDARD
                    .encode(holder_runtime.runtime.mesh_config.identity.public_key),
            }],
        },
    )
    .await?;
    let held_id = match &source_key {
        dynamic_caps::DynamicCapabilitySourceKey::RootAuthority(selector) => {
            dynamic_caps::held_id_for_root(selector)
        }
        dynamic_caps::DynamicCapabilitySourceKey::Grant(grant_id) => {
            dynamic_caps::held_id_for_grant(grant_id)
        }
    };
    Ok(Json(dynamic_caps::ControlDynamicResolveOriginResponse {
        held_id,
        descriptor: resolved_source.descriptor,
        origin_route_id: publish.route_id,
        origin_capability: publish.capability,
        origin_protocol: publish.protocol,
        origin_peer_id,
        origin_peer_key_b64,
        origin_peer_addr,
    }))
}

pub(super) async fn ccs_list_templates(
    State(app): State<CcsApp>,
    headers: HeaderMap,
) -> std::result::Result<Json<TemplateListResponse>, ProtocolApiError> {
    let (record, state) = authorize_request(&app, &headers).await?;
    Ok(Json(list_templates(&state, record.authority_realm_id)?))
}

pub(super) async fn ccs_describe_template(
    State(app): State<CcsApp>,
    headers: HeaderMap,
    AxumPath(template): AxumPath<String>,
) -> std::result::Result<Json<TemplateDescribeResponse>, ProtocolApiError> {
    let (record, state) = authorize_request(&app, &headers).await?;
    Ok(Json(describe_template(
        &state,
        record.authority_realm_id,
        &template,
    )?))
}

pub(super) async fn ccs_resolve_template(
    State(app): State<CcsApp>,
    headers: HeaderMap,
    AxumPath(template): AxumPath<String>,
    Json(request): Json<TemplateResolveRequest>,
) -> std::result::Result<Json<TemplateDescribeResponse>, ProtocolApiError> {
    let (record, state) = authorize_request(&app, &headers).await?;
    Ok(Json(
        resolve_template(&state, record.authority_realm_id, &template, request).await?,
    ))
}

pub(super) async fn ccs_list_children(
    State(app): State<CcsApp>,
    headers: HeaderMap,
) -> std::result::Result<Json<ChildListResponse>, ProtocolApiError> {
    let (record, state) = authorize_request(&app, &headers).await?;
    Ok(Json(list_children(&state, record.authority_realm_id)))
}

pub(super) async fn ccs_create_child(
    State(app): State<CcsApp>,
    headers: HeaderMap,
    Json(request): Json<CreateChildRequest>,
) -> std::result::Result<Json<CreateChildResponse>, ProtocolApiError> {
    let (record, _) = authorize_request(&app, &headers).await?;
    Ok(Json(
        forward_create_child(&app, &record.cap_instance_id, request).await?,
    ))
}

pub(super) async fn ccs_describe_child(
    State(app): State<CcsApp>,
    headers: HeaderMap,
    AxumPath(child): AxumPath<String>,
) -> std::result::Result<Json<ChildDescribeResponse>, ProtocolApiError> {
    let (record, state) = authorize_request(&app, &headers).await?;
    Ok(Json(describe_child(
        &state,
        record.authority_realm_id,
        &child,
    )?))
}

pub(super) async fn ccs_snapshot(
    State(app): State<CcsApp>,
    headers: HeaderMap,
) -> std::result::Result<Json<SnapshotResponse>, ProtocolApiError> {
    let (record, state) = authorize_request(&app, &headers).await?;
    Ok(Json(snapshot(&state, record.authority_realm_id)?))
}

pub(super) async fn ccs_publish_dynamic_capability_origin(
    State(app): State<CcsApp>,
    headers: HeaderMap,
    Json(request): Json<dynamic_caps::PublishDynamicCapabilityOriginRequest>,
) -> std::result::Result<Json<dynamic_caps::PublishDynamicCapabilityOriginResponse>, ProtocolApiError>
{
    authorize_framework_auth_header(&headers, app.control_state_auth_token.as_ref())?;
    Ok(Json(
        publish_dynamic_capability_origin_local(&app, request).await?,
    ))
}

pub(super) async fn ccs_destroy_child(
    State(app): State<CcsApp>,
    headers: HeaderMap,
    AxumPath(child): AxumPath<String>,
) -> std::result::Result<StatusCode, ProtocolApiError> {
    let (record, _) = authorize_request(&app, &headers).await?;
    forward_destroy_child(&app, &record.cap_instance_id, &child).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn authorize_request(
    app: &CcsApp,
    headers: &HeaderMap,
) -> std::result::Result<(CapabilityInstanceRecord, FrameworkControlState), ProtocolApiError> {
    authorize_framework_auth_header(headers, app.router_auth_token.as_ref())?;
    let route_id = required_header(headers, FRAMEWORK_ROUTE_ID_HEADER)?;
    let peer_id = required_header(headers, FRAMEWORK_PEER_ID_HEADER)?;
    let state = fetch_control_state(app).await?;
    let record = authorize_capability_instance(&state, &route_id, &peer_id)
        .map_err(ProtocolApiError::from)?
        .clone();
    Ok((record, state))
}

pub(super) fn authorize_framework_auth_header(
    headers: &HeaderMap,
    expected: &str,
) -> std::result::Result<(), ProtocolApiError> {
    let actual = required_header(headers, FRAMEWORK_AUTH_HEADER)?;
    if actual != expected {
        return Err(ProtocolApiError::unauthorized(
            "invalid authenticated framework request header",
        ));
    }
    Ok(())
}

pub(super) fn required_header(
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

pub(super) async fn fetch_control_state(
    app: &CcsApp,
) -> std::result::Result<FrameworkControlState, ProtocolApiError> {
    let url = format!(
        "{}{}",
        app.control_state_url.trim_end_matches('/'),
        CONTROL_SERVICE_PATH
    );
    let response = app
        .client
        .get(&url)
        .header(FRAMEWORK_AUTH_HEADER, app.control_state_auth_token.as_ref())
        .send()
        .await
        .map_err(|err| {
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

pub(super) async fn forward_create_child(
    app: &CcsApp,
    cap_instance_id: &str,
    request: CreateChildRequest,
) -> std::result::Result<CreateChildResponse, ProtocolApiError> {
    let url = format!(
        "{}/v1/control-state/children",
        app.control_state_url.trim_end_matches('/')
    );
    let response = app
        .client
        .post(&url)
        .header(FRAMEWORK_AUTH_HEADER, app.control_state_auth_token.as_ref())
        .json(&ControlCreateChildRequest {
            cap_instance_id: cap_instance_id.to_string(),
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

pub(super) async fn forward_destroy_child(
    app: &CcsApp,
    cap_instance_id: &str,
    child: &str,
) -> std::result::Result<(), ProtocolApiError> {
    let url = format!(
        "{}/v1/control-state/children/{child}/destroy",
        app.control_state_url.trim_end_matches('/')
    );
    let response = app
        .client
        .post(&url)
        .header(FRAMEWORK_AUTH_HEADER, app.control_state_auth_token.as_ref())
        .json(&ControlDestroyChildRequest {
            cap_instance_id: cap_instance_id.to_string(),
        })
        .send()
        .await
        .map_err(|err| {
            ProtocolApiError::control_state_unavailable(format!(
                "failed to reach authoritative control-state service: {err}"
            ))
        })?;
    parse_control_service_empty(response).await
}

pub(super) async fn parse_control_service_json<T: for<'de> Deserialize<'de>>(
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

pub(super) async fn parse_control_service_empty(
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

pub(super) async fn shutdown_signal() {
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

pub(super) fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to create {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|err| miette::miette!("failed to serialize {}: {err}", path.display()))?;
    write_bytes_atomic(path, &bytes)
}

pub(super) fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
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
    sync_parent_directory(path)?;
    Ok(())
}

pub(super) fn sync_parent_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            fs::File::open(parent)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to open parent directory {}", parent.display()))?
                .sync_all()
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!("failed to sync parent directory {}", parent.display())
                })?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

pub(super) fn read_json<T: for<'de> Deserialize<'de>>(path: &Path, label: &str) -> Result<T> {
    let bytes = fs::read(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {label} {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|err| miette::miette!("invalid {label} {}: {err}", path.display()))
}
