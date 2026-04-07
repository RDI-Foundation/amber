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
            router_auth_token: Arc::<str>::from(plan.router_auth_token),
            control_state_auth_token: Arc::<str>::from(plan.control_state_auth_token),
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

pub(super) async fn ccs_list_templates(
    State(app): State<CcsApp>,
    headers: HeaderMap,
) -> std::result::Result<Json<TemplateListResponse>, ProtocolApiError> {
    let (_, record, state) = authorize_request(&app, &headers).await?;
    Ok(Json(list_templates(&state, record.authority_realm_id)?))
}

pub(super) async fn ccs_describe_template(
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

pub(super) async fn ccs_list_children(
    State(app): State<CcsApp>,
    headers: HeaderMap,
) -> std::result::Result<Json<ChildListResponse>, ProtocolApiError> {
    let (_, record, state) = authorize_request(&app, &headers).await?;
    Ok(Json(list_children(&state, record.authority_realm_id)))
}

pub(super) async fn ccs_create_child(
    State(app): State<CcsApp>,
    headers: HeaderMap,
    Json(request): Json<CreateChildRequest>,
) -> std::result::Result<Json<CreateChildResponse>, ProtocolApiError> {
    let (_, record, _) = authorize_request(&app, &headers).await?;
    Ok(Json(
        forward_create_child(&app, &record.cap_instance_id, request).await?,
    ))
}

pub(super) async fn ccs_describe_child(
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

pub(super) async fn ccs_snapshot(
    State(app): State<CcsApp>,
    headers: HeaderMap,
) -> std::result::Result<Json<SnapshotResponse>, ProtocolApiError> {
    let (_, record, state) = authorize_request(&app, &headers).await?;
    Ok(Json(snapshot(&state, record.authority_realm_id)?))
}

pub(super) async fn ccs_destroy_child(
    State(app): State<CcsApp>,
    headers: HeaderMap,
    AxumPath(child): AxumPath<String>,
) -> std::result::Result<StatusCode, ProtocolApiError> {
    let (_, record, _) = authorize_request(&app, &headers).await?;
    forward_destroy_child(&app, &record.cap_instance_id, &child).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn authorize_request(
    app: &CcsApp,
    headers: &HeaderMap,
) -> std::result::Result<(String, CapabilityInstanceRecord, FrameworkControlState), ProtocolApiError>
{
    authorize_framework_auth_header(headers, app.router_auth_token.as_ref())?;
    let route_id = required_header(headers, FRAMEWORK_ROUTE_ID_HEADER)?;
    let peer_id = required_header(headers, FRAMEWORK_PEER_ID_HEADER)?;
    let state = fetch_control_state(app).await?;
    let record = authorize_capability_instance(&state, &route_id, &peer_id)
        .map_err(ProtocolApiError::from)?
        .clone();
    Ok((peer_id, record, state))
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
