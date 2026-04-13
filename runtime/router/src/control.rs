use super::*;

#[derive(Clone)]
pub(super) struct ControlServiceState {
    external_overrides: ExternalOverrides,
    trust: Arc<TrustBundle>,
    inbound_routes: Arc<InboundRoutes>,
    dynamic_route_overlays: DynamicRouteOverlays,
    dynamic_issuers: DynamicIssuers,
    identity: MeshIdentityPublic,
}

#[derive(Clone)]
pub(super) struct InboundRuntime {
    config: Arc<MeshConfig>,
    trust: Arc<TrustBundle>,
    inbound_routes: Arc<InboundRoutes>,
    dynamic_route_overlays: DynamicRouteOverlays,
    dynamic_issuers: DynamicIssuers,
    external_overrides: ExternalOverrides,
    vetted_external_addrs: VettedExternalAddrs,
    client: Arc<HttpClient>,
    a2a_url_rewrite_table: Arc<a2a::UrlRewriteTable>,
    dynamic_caps: Option<Arc<DynamicCapsRuntime>>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ControlExternalSlot {
    url: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct ControlExportPeer {
    pub(crate) peer_id: String,
    pub(crate) peer_key: String,
    pub(crate) protocol: String,
    #[serde(default)]
    pub(crate) route_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct ControlRouteOverlayPeer {
    pub(crate) peer_id: String,
    pub(crate) peer_key: String,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct ControlRouteOverlay {
    #[serde(default)]
    pub(crate) peers: Vec<ControlRouteOverlayPeer>,
    #[serde(default)]
    pub(crate) inbound_routes: Vec<InboundRoute>,
}

pub(super) const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
pub(super) const MAX_FRAME: usize = 64 * 1024;
pub(super) const MAX_PLAINTEXT: usize = 16 * 1024;
pub(super) const CONTROL_SOCKET_PATH_ENV: &str = "AMBER_ROUTER_CONTROL_SOCKET_PATH";

#[derive(Default)]
pub struct PreboundListeners {
    mesh: Option<TcpListener>,
    outbound_by_route_id: HashMap<String, VecDeque<TcpListener>>,
}

impl PreboundListeners {
    pub fn with_mesh(mut self, listener: TcpListener) -> Self {
        self.mesh = Some(listener);
        self
    }

    pub fn insert_outbound(&mut self, route_id: impl Into<String>, listener: TcpListener) {
        self.outbound_by_route_id
            .entry(route_id.into())
            .or_default()
            .push_back(listener)
    }

    pub(crate) fn take_outbound(&mut self, route_id: &str) -> Option<TcpListener> {
        let listeners = self.outbound_by_route_id.get_mut(route_id)?;
        let listener = listeners.pop_front();
        if listeners.is_empty() {
            self.outbound_by_route_id.remove(route_id);
        }
        listener
    }
}

pub fn config_from_env() -> Result<MeshConfig, RouterError> {
    if let Ok(path) = env::var("AMBER_ROUTER_CONFIG_PATH") {
        let raw = std::fs::read_to_string(&path)
            .map_err(|err| RouterError::InvalidConfig(format!("failed to read {path}: {err}")))?;
        return parse_config_json(&raw, load_identity_from_env);
    }

    if let Ok(b64) = env::var("AMBER_ROUTER_CONFIG_B64") {
        if b64.trim().is_empty() {
            return Err(RouterError::MissingConfig);
        }
        return amber_mesh::decode_config_b64(&b64)
            .map_err(|err| RouterError::InvalidConfig(err.to_string()));
    }

    if let Ok(raw) = env::var("AMBER_ROUTER_CONFIG_JSON") {
        if raw.trim().is_empty() {
            return Err(RouterError::MissingConfig);
        }
        return parse_config_json(&raw, load_identity_from_env);
    }

    Err(RouterError::MissingConfig)
}

pub(super) fn parse_config_json(
    raw: &str,
    identity: impl FnOnce() -> Result<MeshIdentitySecret, RouterError>,
) -> Result<MeshConfig, RouterError> {
    if let Ok(parsed) = serde_json::from_str::<MeshConfig>(raw) {
        return Ok(parsed);
    }
    let public: MeshConfigPublic =
        serde_json::from_str(raw).map_err(|err| RouterError::InvalidConfig(err.to_string()))?;
    let secret = identity()?;
    public
        .with_identity_secret(secret)
        .map_err(|err| RouterError::InvalidConfig(err.to_string()))
}

pub(super) fn load_identity_from_env() -> Result<MeshIdentitySecret, RouterError> {
    if let Ok(path) = env::var("AMBER_ROUTER_IDENTITY_PATH") {
        let raw = std::fs::read_to_string(&path)
            .map_err(|err| RouterError::InvalidConfig(format!("failed to read {path}: {err}")))?;
        return parse_identity_json(&raw);
    }
    if let Ok(raw) = env::var("AMBER_ROUTER_IDENTITY_JSON") {
        return parse_identity_json(&raw);
    }
    Err(RouterError::MissingIdentity)
}

pub(super) fn parse_identity_json(raw: &str) -> Result<MeshIdentitySecret, RouterError> {
    if raw.trim().is_empty() {
        return Err(RouterError::MissingIdentity);
    }
    serde_json::from_str(raw).map_err(|err| RouterError::InvalidConfig(err.to_string()))
}

pub async fn run(config: MeshConfig) -> Result<(), RouterError> {
    run_with_listeners(config, PreboundListeners::default()).await
}

pub async fn run_with_listeners(
    config: MeshConfig,
    mut listeners_by_route: PreboundListeners,
) -> Result<(), RouterError> {
    let trust = Arc::new(TrustBundle::new(&config)?);
    let inbound_routes = Arc::new(build_inbound_routes(&config)?);
    validate_outbound_routes(&config)?;
    let a2a_url_rewrite_table = Arc::new(a2a::UrlRewriteTable::from_routes(
        &config.inbound,
        &config.outbound,
    ));
    let dynamic_issuers = Arc::new(RwLock::new(HashMap::new()));
    let dynamic_route_overlays = Arc::new(RwLock::new(HashMap::new()));
    let identity_public = MeshIdentityPublic::from_identity(&config.identity);
    let control_allow = match config.control_allow.as_ref() {
        Some(entries) => Some(resolve_control_allowlist(entries).await?),
        None => None,
    };
    let config = Arc::new(config);
    let external_overrides = Arc::new(RwLock::new(HashMap::new()));
    let (client, vetted_external_addrs) = build_client();
    let client = Arc::new(client);
    let dynamic_caps = DynamicCapsRuntime::build(
        config.clone(),
        client.clone(),
        a2a_url_rewrite_table.clone(),
    )?;
    let mut listeners = JoinSet::new();

    {
        listeners.spawn(run_mesh_listener(
            InboundRuntime {
                config: config.clone(),
                trust: trust.clone(),
                inbound_routes: inbound_routes.clone(),
                dynamic_route_overlays: dynamic_route_overlays.clone(),
                dynamic_issuers: dynamic_issuers.clone(),
                external_overrides: external_overrides.clone(),
                vetted_external_addrs: vetted_external_addrs.clone(),
                client: client.clone(),
                a2a_url_rewrite_table: a2a_url_rewrite_table.clone(),
                dynamic_caps: dynamic_caps.clone(),
            },
            listeners_by_route.mesh.take(),
        ));
    }

    for route in config.outbound.clone() {
        let config = config.clone();
        let trust = trust.clone();
        let a2a_url_rewrite_table = a2a_url_rewrite_table.clone();
        let prebound_listener = listeners_by_route.take_outbound(route.route_id.as_str());
        listeners.spawn(run_outbound_listener(
            route,
            config,
            trust,
            a2a_url_rewrite_table,
            dynamic_caps.clone(),
            prebound_listener,
        ));
    }

    if let Some(dynamic_caps) = dynamic_caps.clone() {
        listeners.spawn(run_dynamic_caps_server(dynamic_caps));
    }

    let control_socket_path = env::var(CONTROL_SOCKET_PATH_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    if let Some(path) = control_socket_path.clone() {
        #[cfg(unix)]
        {
            listeners.spawn(run_control_server_unix(
                path,
                ControlServiceState {
                    external_overrides: external_overrides.clone(),
                    trust: trust.clone(),
                    inbound_routes: inbound_routes.clone(),
                    dynamic_route_overlays: dynamic_route_overlays.clone(),
                    dynamic_issuers: dynamic_issuers.clone(),
                    identity: identity_public.clone(),
                },
            ));
        }
        #[cfg(not(unix))]
        {
            return Err(RouterError::InvalidConfig(format!(
                "{CONTROL_SOCKET_PATH_ENV} is only supported on unix targets"
            )));
        }
    }

    if control_socket_path.is_none()
        && let Some(addr) = config.control_listen
    {
        let control_allow = control_allow.clone();
        listeners.spawn(run_control_server(
            addr,
            control_allow,
            ControlServiceState {
                external_overrides: external_overrides.clone(),
                trust: trust.clone(),
                inbound_routes: inbound_routes.clone(),
                dynamic_route_overlays: dynamic_route_overlays.clone(),
                dynamic_issuers: dynamic_issuers.clone(),
                identity: identity_public.clone(),
            },
        ));
    }

    if listeners.is_empty() {
        return Err(RouterError::Transport(
            "no listener tasks were started".to_string(),
        ));
    }

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    let result = tokio::select! {
        () = &mut shutdown => {
            tracing::info!("router received shutdown signal");
            Ok(())
        }
        listener = listeners.join_next() => {
            let Some(listener) = listener else {
                return Err(RouterError::Transport(
                    "no listener tasks were started".to_string(),
                ));
            };
            match listener {
                Ok(Ok(())) => Err(RouterError::Transport(
                    "listener task exited unexpectedly".to_string(),
                )),
                Ok(Err(err)) => Err(err),
                Err(err) => Err(RouterError::Transport(format!(
                    "listener task panicked: {err}"
                ))),
            }
        }
    };

    listeners.abort_all();
    while listeners.join_next().await.is_some() {}
    result
}

pub(super) async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(sigterm) => sigterm,
            Err(err) => {
                tracing::warn!("failed to install SIGTERM handler: {err}");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        let mut sighup = match signal(SignalKind::hangup()) {
            Ok(sighup) => sighup,
            Err(err) => {
                tracing::warn!("failed to install SIGHUP handler: {err}");
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = sigterm.recv() => {}
                }
                return;
            }
        };

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
            _ = sighup.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

pub(super) async fn run_mesh_listener(
    state: InboundRuntime,
    prebound_listener: Option<TcpListener>,
) -> Result<(), RouterError> {
    let listener = if let Some(listener) = prebound_listener {
        listener
    } else {
        TcpListener::bind(state.config.mesh_listen)
            .await
            .map_err(|source| RouterError::BindFailed {
                addr: state.config.mesh_listen,
                source,
            })?
    };

    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_inbound(stream, state).await {
                tracing::warn!(target: "amber.internal", "mesh tcp connection failed: {err}");
            }
        });
    }
}

pub(super) async fn handle_inbound(
    stream: tokio::net::TcpStream,
    state: InboundRuntime,
) -> Result<(), RouterError> {
    let InboundRuntime {
        config,
        trust,
        inbound_routes,
        dynamic_route_overlays,
        dynamic_issuers,
        external_overrides,
        vetted_external_addrs,
        client,
        a2a_url_rewrite_table,
        dynamic_caps,
    } = state;
    let noise_keys = noise_keys_for_identity(&config.identity)?;
    let mut session = accept_noise(stream, &noise_keys, &trust).await?;
    let remote_id = session
        .remote_id
        .clone()
        .ok_or_else(|| RouterError::Auth("unknown peer".to_string()))?;
    let open = session.recv_open().await?;
    let route = {
        let overlays = dynamic_route_overlays.read().await;
        let issuers = dynamic_issuers.read().await;
        resolve_inbound_route(
            inbound_routes.as_ref(),
            &overlays,
            &open,
            &remote_id,
            &issuers,
        )?
        .clone()
    };

    match route.target {
        InboundTarget::Local { port } => {
            if route.protocol == MeshProtocol::Http {
                let plugins = resolve_http_plugins(&route.http_plugins, a2a_url_rewrite_table);
                proxy_noise_to_local_http(
                    &mut session,
                    route.route_id.clone().into(),
                    remote_id.clone().into(),
                    port,
                    client.clone(),
                    plugins,
                    HttpExchangeLabels::inbound_from_route(
                        config.identity.id.clone().into(),
                        remote_id.clone().into(),
                        &route,
                        &open,
                    ),
                    dynamic_caps.clone(),
                )
                .await?;
            } else {
                let target = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
                proxy_noise_to_plain(&mut session, target).await?;
            }
        }
        InboundTarget::External {
            ref url_env,
            optional,
        } => match route.protocol {
            MeshProtocol::Http => {
                let framework_route_id = (url_env
                    == amber_mesh::FRAMEWORK_COMPONENT_CONTROLLER_URL_ENV)
                    .then(|| Arc::<str>::from(route.route_id.as_str()));
                let framework_peer_id = (url_env
                    == amber_mesh::FRAMEWORK_COMPONENT_CONTROLLER_URL_ENV)
                    .then(|| Arc::<str>::from(remote_id.as_str()));
                proxy_noise_to_external(
                    &mut session,
                    ExternalProxyRequest {
                        route_id: framework_route_id,
                        peer_id: framework_peer_id,
                        labels: HttpExchangeLabels::inbound_from_route(
                            config.identity.id.clone().into(),
                            remote_id.clone().into(),
                            &route,
                            &open,
                        ),
                        target: ExternalTarget {
                            name: route.capability.clone(),
                            url_env: url_env.clone(),
                            optional,
                            url_override: None,
                        },
                        client: client.clone(),
                        config: config.clone(),
                        external_overrides: external_overrides.clone(),
                        vetted_external_addrs: vetted_external_addrs.clone(),
                    },
                )
                .await?;
            }
            MeshProtocol::Tcp => {
                let override_url = {
                    external_overrides
                        .read()
                        .await
                        .get(&route.capability)
                        .cloned()
                }
                .and_then(|value| {
                    let trimmed = value.trim().to_string();
                    (!trimmed.is_empty()).then_some(trimmed)
                });
                if let Some(override_url) = override_url {
                    if maybe_proxy_mesh_external(
                        &mut session,
                        &route.capability,
                        route.protocol,
                        &override_url,
                        &config,
                    )
                    .await?
                    {
                        return Ok(());
                    }

                    proxy_noise_to_external_tcp(
                        &mut session,
                        ExternalTarget {
                            name: route.capability.clone(),
                            url_env: url_env.clone(),
                            optional,
                            url_override: Some(override_url),
                        },
                    )
                    .await?;
                    return Ok(());
                }

                if let Ok(raw) = env::var(url_env) {
                    let trimmed = raw.trim();
                    if maybe_proxy_mesh_external(
                        &mut session,
                        &route.capability,
                        route.protocol,
                        trimmed,
                        &config,
                    )
                    .await?
                    {
                        return Ok(());
                    }
                }

                proxy_noise_to_external_tcp(
                    &mut session,
                    ExternalTarget {
                        name: route.capability.clone(),
                        url_env: url_env.clone(),
                        optional,
                        url_override: None,
                    },
                )
                .await?;
            }
        },
        InboundTarget::MeshForward {
            ref peer_addr,
            ref peer_id,
            ref route_id,
            ref capability,
        } => {
            let outbound = connect_noise(peer_addr, peer_id, &config, &trust).await?;
            let labels = HttpExchangeLabels::inbound_from_route(
                config.identity.id.clone().into(),
                remote_id.clone().into(),
                &route,
                &open,
            );
            let open = OpenFrame {
                route_id: route_id.clone(),
                capability: capability.clone(),
                protocol: route.protocol,
                slot: open.slot.clone(),
                capability_kind: route
                    .capability_kind
                    .clone()
                    .or_else(|| open.capability_kind.clone()),
                capability_profile: route
                    .capability_profile
                    .clone()
                    .or_else(|| open.capability_profile.clone()),
            };
            outbound.send_open(&open).await?;
            if route.protocol == MeshProtocol::Http {
                let plugins = resolve_http_plugins(&route.http_plugins, a2a_url_rewrite_table);
                proxy_noise_to_noise_http(
                    &mut session,
                    outbound,
                    route.route_id.clone().into(),
                    remote_id.clone().into(),
                    plugins,
                    labels,
                )
                .await?;
            } else {
                proxy_noise_to_noise(&mut session, outbound).await?;
            }
        }
    }

    Ok(())
}

pub(super) async fn maybe_proxy_mesh_external(
    session: &mut NoiseSession,
    capability: &str,
    protocol: MeshProtocol,
    url: &str,
    config: &MeshConfig,
) -> Result<bool, RouterError> {
    if !url.starts_with("mesh://") {
        return Ok(false);
    }
    let mesh = parse_mesh_external(url)?;
    let outbound =
        connect_noise_with_key(&mesh.peer_addr, &mesh.peer_id, mesh.peer_key, config).await?;
    let open = OpenFrame {
        route_id: mesh
            .route_id
            .clone()
            .unwrap_or_else(|| component_route_id(&mesh.peer_id, capability, protocol)),
        capability: mesh
            .capability
            .clone()
            .unwrap_or_else(|| capability.to_string()),
        protocol,
        slot: None,
        capability_kind: None,
        capability_profile: None,
    };
    outbound.send_open(&open).await?;
    proxy_noise_to_noise(session, outbound).await?;
    Ok(true)
}

pub(super) async fn run_outbound_listener(
    route: OutboundRoute,
    config: Arc<MeshConfig>,
    trust: Arc<TrustBundle>,
    a2a_url_rewrite_table: Arc<a2a::UrlRewriteTable>,
    dynamic_caps: Option<Arc<DynamicCapsRuntime>>,
    prebound_listener: Option<TcpListener>,
) -> Result<(), RouterError> {
    let listen_ip = route
        .listen_addr
        .as_deref()
        .unwrap_or("127.0.0.1")
        .parse()
        .map_err(|_| RouterError::InvalidConfig("invalid listen address".to_string()))?;
    let listen_addr = SocketAddr::new(listen_ip, route.listen_port);
    let listener = if let Some(listener) = prebound_listener {
        listener
    } else {
        TcpListener::bind(listen_addr)
            .await
            .map_err(|source| RouterError::BindFailed {
                addr: listen_addr,
                source,
            })?
    };

    loop {
        let (stream, _) = listener.accept().await?;
        let route = route.clone();
        let config = config.clone();
        let trust = trust.clone();
        let a2a_url_rewrite_table = a2a_url_rewrite_table.clone();
        let dynamic_caps = dynamic_caps.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_outbound(
                stream,
                route,
                config,
                trust,
                a2a_url_rewrite_table,
                dynamic_caps,
            )
            .await
            {
                tracing::warn!(target: "amber.internal", "outbound connection failed: {err}");
            }
        });
    }
}

pub(super) async fn handle_outbound(
    stream: tokio::net::TcpStream,
    route: OutboundRoute,
    config: Arc<MeshConfig>,
    trust: Arc<TrustBundle>,
    a2a_url_rewrite_table: Arc<a2a::UrlRewriteTable>,
    dynamic_caps: Option<Arc<DynamicCapsRuntime>>,
) -> Result<(), RouterError> {
    let mut outbound = connect_noise(&route.peer_addr, &route.peer_id, &config, &trust).await?;

    let open = OpenFrame {
        route_id: route.route_id.clone(),
        capability: route.capability.clone(),
        protocol: route.protocol,
        slot: Some(route.slot.clone()),
        capability_kind: route.capability_kind.clone(),
        capability_profile: route.capability_profile.clone(),
    };
    outbound.send_open(&open).await?;
    if route.protocol == MeshProtocol::Http {
        let plugins = resolve_http_plugins(&route.http_plugins, a2a_url_rewrite_table);
        proxy_local_http_to_noise(
            &mut outbound,
            route.route_id.clone().into(),
            config.identity.id.clone().into(),
            stream,
            plugins,
            HttpExchangeLabels::outbound_from_route(config.identity.id.clone().into(), &route),
            dynamic_caps,
        )
        .await?;
    } else {
        proxy_noise_to_plain(&mut outbound, stream).await?;
    }

    Ok(())
}

pub(super) async fn run_control_server(
    addr: SocketAddr,
    control_allow: Option<ControlAllowlist>,
    state: ControlServiceState,
) -> Result<(), RouterError> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|source| RouterError::BindFailed { addr, source })?;

    loop {
        let (stream, peer) = listener.accept().await?;
        let control_allow = control_allow.clone();
        let state = state.clone();
        tokio::spawn(async move {
            let allowed = control_allow
                .as_ref()
                .is_none_or(|allow| allow.contains(&peer.ip()));
            if let Err(err) = serve_control_connection(stream, state, allowed).await {
                tracing::warn!(target: "amber.internal", "control connection failed: {err}");
            }
        });
    }
}

#[cfg(unix)]
pub(super) async fn run_control_server_unix(
    path: String,
    state: ControlServiceState,
) -> Result<(), RouterError> {
    let listener = bind_unix_listener(path.as_str())?;

    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = serve_control_connection(stream, state, true).await {
                tracing::warn!(target: "amber.internal", "control unix connection failed: {err}");
            }
        });
    }
}

#[cfg(unix)]
pub(super) fn bind_unix_listener(path: &str) -> Result<UnixListener, RouterError> {
    use std::os::unix::fs::PermissionsExt as _;

    let path = path.trim().to_string();
    if path.is_empty() {
        return Err(RouterError::InvalidConfig(format!(
            "{CONTROL_SOCKET_PATH_ENV} must not be empty"
        )));
    }
    let socket_path = Path::new(&path);
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| RouterError::BindUnixFailed {
            path: path.clone(),
            source,
        })?;
    }
    if socket_path.exists() {
        std::fs::remove_file(socket_path).map_err(|source| RouterError::BindUnixFailed {
            path: path.clone(),
            source,
        })?;
    }
    let listener =
        UnixListener::bind(socket_path).map_err(|source| RouterError::BindUnixFailed {
            path: path.clone(),
            source,
        })?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600)).map_err(
        |source| RouterError::BindUnixFailed {
            path: path.clone(),
            source,
        },
    )?;
    Ok(listener)
}

pub(super) async fn serve_control_connection<IO>(
    stream: IO,
    state: ControlServiceState,
    allowed: bool,
) -> Result<(), hyper::Error>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |req| {
        let state = state.clone();
        async move {
            if !allowed {
                return Ok(error_response(
                    StatusCode::FORBIDDEN,
                    "control access denied",
                ));
            }
            let ControlServiceState {
                external_overrides,
                trust,
                inbound_routes,
                dynamic_route_overlays,
                dynamic_issuers,
                identity,
            } = state;
            control_service(
                req,
                external_overrides,
                trust,
                inbound_routes,
                dynamic_route_overlays,
                dynamic_issuers,
                identity,
            )
            .await
        }
    });
    http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .await
}

pub(super) async fn resolve_control_allowlist(
    entries: &[String],
) -> Result<ControlAllowlist, RouterError> {
    let mut allowed = HashSet::new();
    for entry in entries {
        let entry = entry.trim();
        if entry.is_empty() {
            return Err(RouterError::InvalidConfig(
                "control allow entry must not be empty".to_string(),
            ));
        }
        if let Ok(ip) = entry.parse::<IpAddr>() {
            allowed.insert(ip);
            continue;
        }
        if entry.contains(':') {
            return Err(RouterError::InvalidConfig(format!(
                "control allow entry must be a hostname or IP (got {entry})"
            )));
        }
        let host = format!("{entry}:0");
        let addrs = tokio::net::lookup_host(host).await.map_err(|err| {
            RouterError::InvalidConfig(format!(
                "failed to resolve control allow entry {entry}: {err}"
            ))
        })?;
        let mut found = false;
        for addr in addrs {
            allowed.insert(addr.ip());
            found = true;
        }
        if !found {
            return Err(RouterError::InvalidConfig(format!(
                "control allow entry {entry} did not resolve to an address"
            )));
        }
    }
    Ok(Arc::new(allowed))
}

pub(super) async fn control_service(
    req: Request<Incoming>,
    external_overrides: ExternalOverrides,
    trust: Arc<TrustBundle>,
    inbound_routes: Arc<InboundRoutes>,
    dynamic_route_overlays: DynamicRouteOverlays,
    dynamic_issuers: DynamicIssuers,
    identity: MeshIdentityPublic,
) -> Result<Response<BoxBody>, hyper::Error> {
    let path = req.uri().path().to_string();
    let Some(route) = control_route(&path) else {
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            "unknown control route",
        ));
    };

    match route {
        ControlRoute::Identity => match *req.method() {
            Method::GET => Ok(json_response(StatusCode::OK, &identity)),
            _ => Ok(error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed",
            )),
        },
        ControlRoute::ExternalSlot(slot) => match *req.method() {
            Method::PUT => {
                let body = req.into_body().collect().await?.to_bytes();
                let payload: ControlExternalSlot = match serde_json::from_slice(&body) {
                    Ok(value) => value,
                    Err(err) => {
                        return Ok(error_response(
                            StatusCode::BAD_REQUEST,
                            &format!("invalid json: {err}"),
                        ));
                    }
                };
                let url = payload.url.trim();
                if url.is_empty() {
                    return Ok(error_response(
                        StatusCode::BAD_REQUEST,
                        "url must not be empty",
                    ));
                }
                if url.starts_with("mesh://") {
                    if let Err(err) = parse_mesh_external(url) {
                        return Ok(error_response(
                            StatusCode::BAD_REQUEST,
                            &format!("invalid mesh url: {err}"),
                        ));
                    }
                } else {
                    let parsed = match Url::parse(url) {
                        Ok(parsed) => parsed,
                        Err(err) => {
                            return Ok(error_response(
                                StatusCode::BAD_REQUEST,
                                &format!("invalid url: {err}"),
                            ));
                        }
                    };
                    if !is_http_scheme(&parsed) {
                        return Ok(error_response(
                            StatusCode::BAD_REQUEST,
                            "url must be http/https or mesh://",
                        ));
                    }
                }

                external_overrides
                    .write()
                    .await
                    .insert(slot.to_string(), url.to_string());
                Ok(control_empty(StatusCode::NO_CONTENT))
            }
            Method::DELETE => {
                external_overrides.write().await.remove(slot);
                Ok(control_empty(StatusCode::NO_CONTENT))
            }
            _ => Ok(error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed",
            )),
        },
        ControlRoute::Export(export) => match *req.method() {
            Method::PUT => {
                let body = req.into_body().collect().await?.to_bytes();
                let payload: ControlExportPeer = match serde_json::from_slice(&body) {
                    Ok(value) => value,
                    Err(err) => {
                        return Ok(error_response(
                            StatusCode::BAD_REQUEST,
                            &format!("invalid json: {err}"),
                        ));
                    }
                };
                if let Err(err) = register_export_peer(
                    export,
                    payload,
                    trust.as_ref(),
                    inbound_routes.as_ref(),
                    &dynamic_route_overlays,
                    &dynamic_issuers,
                    &identity.id,
                )
                .await
                {
                    return Ok(error_response(StatusCode::BAD_REQUEST, &err));
                }
                Ok(control_empty(StatusCode::NO_CONTENT))
            }
            Method::DELETE => {
                let body = req.into_body().collect().await?.to_bytes();
                let payload: ControlExportPeer = match serde_json::from_slice(&body) {
                    Ok(value) => value,
                    Err(err) => {
                        return Ok(error_response(
                            StatusCode::BAD_REQUEST,
                            &format!("invalid json: {err}"),
                        ));
                    }
                };
                if let Err(err) = unregister_export_peer(
                    export,
                    payload,
                    trust.as_ref(),
                    inbound_routes.as_ref(),
                    &dynamic_route_overlays,
                    &dynamic_issuers,
                )
                .await
                {
                    return Ok(error_response(StatusCode::BAD_REQUEST, &err));
                }
                Ok(control_empty(StatusCode::NO_CONTENT))
            }
            _ => Ok(error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed",
            )),
        },
        ControlRoute::Overlay(overlay_id) => match *req.method() {
            Method::PUT => {
                let body = req.into_body().collect().await?.to_bytes();
                let payload: ControlRouteOverlay = match serde_json::from_slice(&body) {
                    Ok(value) => value,
                    Err(err) => {
                        return Ok(error_response(
                            StatusCode::BAD_REQUEST,
                            &format!("invalid json: {err}"),
                        ));
                    }
                };
                if let Err(err) = apply_route_overlay(
                    overlay_id,
                    payload,
                    trust.as_ref(),
                    inbound_routes.as_ref(),
                    &dynamic_route_overlays,
                    &dynamic_issuers,
                )
                .await
                {
                    return Ok(error_response(StatusCode::BAD_REQUEST, &err));
                }
                Ok(control_empty(StatusCode::NO_CONTENT))
            }
            Method::DELETE => {
                revoke_route_overlay(
                    overlay_id,
                    trust.as_ref(),
                    &dynamic_route_overlays,
                    &dynamic_issuers,
                )
                .await;
                Ok(control_empty(StatusCode::NO_CONTENT))
            }
            _ => Ok(error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed",
            )),
        },
    }
}

pub(super) enum ControlRoute<'a> {
    Identity,
    ExternalSlot(&'a str),
    Export(&'a str),
    Overlay(&'a str),
}

pub(super) fn control_route(path: &str) -> Option<ControlRoute<'_>> {
    let mut parts = path.trim_matches('/').split('/');
    let prefix = parts.next()?;
    match prefix {
        "external-slots" => {
            let slot = parts.next()?;
            if parts.next().is_some() {
                return None;
            }
            Some(ControlRoute::ExternalSlot(slot))
        }
        "exports" => {
            let export = parts.next()?;
            if parts.next().is_some() {
                return None;
            }
            Some(ControlRoute::Export(export))
        }
        "identity" => {
            if parts.next().is_some() {
                return None;
            }
            Some(ControlRoute::Identity)
        }
        "overlays" => {
            let overlay_id = parts.next()?;
            if parts.next().is_some() {
                return None;
            }
            Some(ControlRoute::Overlay(overlay_id))
        }
        _ => None,
    }
}

pub(super) fn control_empty(status: StatusCode) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_LENGTH, "0")
        .body(
            Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap_or_else(|_| {
            Response::new(
                Full::new(Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
        })
}

pub(super) fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Response<BoxBody> {
    let body = match serde_json::to_vec(value) {
        Ok(body) => body,
        Err(err) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to serialize response: {err}"),
            );
        }
    };
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_LENGTH, body.len().to_string())
        .body(
            Full::new(Bytes::from(body))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap_or_else(|_| {
            Response::new(
                Full::new(Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
        })
}

pub(super) async fn register_export_peer(
    export: &str,
    payload: ControlExportPeer,
    trust: &TrustBundle,
    inbound_routes: &InboundRoutes,
    dynamic_route_overlays: &DynamicRouteOverlays,
    dynamic_issuers: &DynamicIssuers,
    router_id: &str,
) -> Result<(), String> {
    let peer_id = validated_control_peer_id(&payload.peer_id, "peer_id")?;
    if peer_id == router_id {
        return Err("peer_id must not be the router identity".to_string());
    }
    let peer_key = decode_peer_key(&payload.peer_key)?;
    let protocol = control_protocol(payload.protocol.trim())?;
    let overlays = dynamic_route_overlays.read().await;
    let route = resolve_export_route(
        export,
        protocol,
        payload.route_id.as_deref(),
        inbound_routes,
        &overlays,
    )?;

    let peer = MeshPeer {
        id: peer_id.to_string(),
        public_key: peer_key,
    };
    trust
        .insert_peer(&peer)
        .await
        .map_err(|err| format!("invalid peer: {err}"))?;

    let mut issuers = dynamic_issuers.write().await;
    issuers
        .entry(route.route_id.clone())
        .or_default()
        .insert(peer.id.clone());
    Ok(())
}

pub(super) async fn unregister_export_peer(
    export: &str,
    payload: ControlExportPeer,
    trust: &TrustBundle,
    inbound_routes: &InboundRoutes,
    dynamic_route_overlays: &DynamicRouteOverlays,
    dynamic_issuers: &DynamicIssuers,
) -> Result<(), String> {
    let peer_id = validated_control_peer_id(&payload.peer_id, "peer_id")?;
    let peer_key = decode_peer_key(&payload.peer_key)?;
    let protocol = control_protocol(payload.protocol.trim())?;
    let overlays = dynamic_route_overlays.read().await;
    let route = resolve_export_route(
        export,
        protocol,
        payload.route_id.as_deref(),
        inbound_routes,
        &overlays,
    )?;

    let mut issuers = dynamic_issuers.write().await;
    let Some(route_issuers) = issuers.get(&route.route_id) else {
        return Ok(());
    };
    if !route_issuers.contains(peer_id) {
        return Ok(());
    }
    trust
        .remove_peer(&MeshPeer {
            id: peer_id.to_string(),
            public_key: peer_key,
        })
        .await
        .map_err(|err| format!("invalid peer: {err}"))?;
    let remove_route = if let Some(route_issuers) = issuers.get_mut(&route.route_id) {
        route_issuers.remove(peer_id);
        route_issuers.is_empty()
    } else {
        false
    };
    if remove_route {
        issuers.remove(&route.route_id);
    }
    Ok(())
}

fn resolve_export_route<'a>(
    export: &str,
    protocol: MeshProtocol,
    route_id: Option<&str>,
    inbound_routes: &'a InboundRoutes,
    overlays: &'a HashMap<String, DynamicRouteOverlay>,
) -> Result<&'a InboundRoute, String> {
    if let Some(route_id) = route_id
        .map(str::trim)
        .filter(|route_id| !route_id.is_empty())
    {
        return effective_inbound_routes(inbound_routes, overlays)
            .find(|route| {
                route.route_id == route_id
                    && route.capability == export
                    && route.protocol == protocol
                    && matches!(route.target, InboundTarget::MeshForward { .. })
            })
            .ok_or_else(|| {
                format!(
                    "route {} is not a mesh export for capability {} and protocol {}",
                    route_id,
                    export,
                    protocol_string(protocol)
                )
            });
    }

    let mut export_routes = effective_inbound_routes(inbound_routes, overlays).filter(|route| {
        route.capability == export
            && route.protocol == protocol
            && matches!(route.target, InboundTarget::MeshForward { .. })
    });
    let Some(route) = export_routes.next() else {
        return Err(format!("capability {} is not an export", export));
    };
    if export_routes.next().is_some() {
        return Err(format!(
            "ambiguous export {} for protocol {}",
            export,
            protocol_string(protocol)
        ));
    }
    Ok(route)
}

pub(super) async fn apply_route_overlay(
    overlay_id: &str,
    payload: ControlRouteOverlay,
    trust: &TrustBundle,
    inbound_routes: &InboundRoutes,
    dynamic_route_overlays: &DynamicRouteOverlays,
    dynamic_issuers: &DynamicIssuers,
) -> Result<(), String> {
    if overlay_id.trim().is_empty() {
        return Err("overlay id must not be empty".to_string());
    }

    let mut seen_route_ids = HashSet::new();
    let mut routes = HashMap::new();
    let mut static_issuer_grants = HashMap::<String, HashSet<String>>::new();
    for route in payload.inbound_routes {
        if !seen_route_ids.insert(route.route_id.clone()) {
            return Err("overlay contains duplicate route ids".to_string());
        }
        if let Some(static_route) = inbound_routes.get(&route.route_id) {
            if !static_route_compatible_with_overlay(static_route, &route) {
                return Err(format!(
                    "overlay route {} collides with a static route",
                    route.route_id
                ));
            }
            static_issuer_grants
                .entry(route.route_id.clone())
                .or_default()
                .extend(route.allowed_issuers.iter().cloned());
            continue;
        }
        routes.insert(route.route_id.clone(), route);
    }

    {
        let overlays = dynamic_route_overlays.read().await;
        for route_id in routes.keys() {
            if overlays
                .iter()
                .filter(|(existing_id, _)| existing_id.as_str() != overlay_id)
                .any(|(_, overlay)| overlay.routes.contains_key(route_id))
            {
                return Err(format!(
                    "overlay route {route_id} collides with another overlay"
                ));
            }
        }
    }

    let mut overlay_peers = Vec::with_capacity(payload.peers.len());
    for peer in payload.peers {
        let peer_id = validated_control_peer_id(&peer.peer_id, "overlay peer_id")?;
        let mesh_peer = MeshPeer {
            id: peer_id.to_string(),
            public_key: decode_peer_key(&peer.peer_key)?,
        };
        overlay_peers.push(mesh_peer);
    }

    let existing_overlay = dynamic_route_overlays.write().await.remove(overlay_id);
    if let Some(existing_overlay) = existing_overlay.as_ref() {
        let mut issuers = dynamic_issuers.write().await;
        remove_dynamic_issuer_grants(&mut issuers, &existing_overlay.static_issuer_grants);
        for peer in &existing_overlay.peers {
            if let Err(remove_err) = trust.remove_peer(peer).await {
                trust
                    .remove_dynamic_peer_by_id(&peer.id)
                    .await
                    .map_err(|cleanup_err| {
                        format!(
                            "failed to replace overlay peer {}: {remove_err}; fallback cleanup \
                             failed: {cleanup_err}",
                            peer.id
                        )
                    })?;
            }
        }
    }

    let mut inserted_peers = Vec::new();
    for peer in &overlay_peers {
        if let Err(err) = trust.insert_peer(peer).await {
            for inserted_peer in inserted_peers.iter().rev() {
                let _ = trust.remove_peer(inserted_peer).await;
            }
            if let Some(existing_overlay) = existing_overlay {
                for existing_peer in &existing_overlay.peers {
                    let _ = trust.insert_peer(existing_peer).await;
                }
                let mut issuers = dynamic_issuers.write().await;
                add_dynamic_issuer_grants(&mut issuers, &existing_overlay.static_issuer_grants);
                dynamic_route_overlays
                    .write()
                    .await
                    .insert(overlay_id.to_string(), existing_overlay);
            }
            return Err(format!("invalid overlay peer {}: {err}", peer.id));
        }
        inserted_peers.push(peer.clone());
    }

    dynamic_route_overlays.write().await.insert(
        overlay_id.to_string(),
        DynamicRouteOverlay {
            routes,
            peers: overlay_peers,
            static_issuer_grants: static_issuer_grants.clone(),
        },
    );
    if !static_issuer_grants.is_empty() {
        let mut issuers = dynamic_issuers.write().await;
        add_dynamic_issuer_grants(&mut issuers, &static_issuer_grants);
    }
    Ok(())
}

pub(super) async fn revoke_route_overlay(
    overlay_id: &str,
    trust: &TrustBundle,
    dynamic_route_overlays: &DynamicRouteOverlays,
    dynamic_issuers: &DynamicIssuers,
) {
    let removed = dynamic_route_overlays.write().await.remove(overlay_id);
    if let Some(overlay) = removed {
        for peer in &overlay.peers {
            if trust.remove_peer(peer).await.is_err() {
                let _ = trust.remove_dynamic_peer_by_id(&peer.id).await;
            }
        }
        let mut issuers = dynamic_issuers.write().await;
        for route_id in overlay.routes.keys() {
            issuers.remove(route_id);
        }
        remove_dynamic_issuer_grants(&mut issuers, &overlay.static_issuer_grants);
    }
}

fn static_route_compatible_with_overlay(
    static_route: &InboundRoute,
    overlay_route: &InboundRoute,
) -> bool {
    static_route.capability == overlay_route.capability
        && static_route.capability_kind == overlay_route.capability_kind
        && static_route.capability_profile == overlay_route.capability_profile
        && static_route.protocol == overlay_route.protocol
        && static_route.http_plugins == overlay_route.http_plugins
        && static_route.target == overlay_route.target
}

fn add_dynamic_issuer_grants(
    issuers: &mut HashMap<String, HashSet<String>>,
    grants: &HashMap<String, HashSet<String>>,
) {
    for (route_id, route_grants) in grants {
        issuers
            .entry(route_id.clone())
            .or_default()
            .extend(route_grants.iter().cloned());
    }
}

fn remove_dynamic_issuer_grants(
    issuers: &mut HashMap<String, HashSet<String>>,
    grants: &HashMap<String, HashSet<String>>,
) {
    for (route_id, route_grants) in grants {
        let Some(existing) = issuers.get_mut(route_id) else {
            continue;
        };
        for issuer in route_grants {
            existing.remove(issuer);
        }
        if existing.is_empty() {
            issuers.remove(route_id);
        }
    }
}

fn effective_inbound_routes<'a>(
    inbound_routes: &'a InboundRoutes,
    dynamic_route_overlays: &'a HashMap<String, DynamicRouteOverlay>,
) -> impl Iterator<Item = &'a InboundRoute> + 'a {
    inbound_routes.values().chain(
        dynamic_route_overlays
            .values()
            .flat_map(|overlay| overlay.routes.values()),
    )
}

fn validated_control_peer_id<'a>(raw: &'a str, field_name: &str) -> Result<&'a str, String> {
    let peer_id = raw.trim();
    if peer_id.is_empty() {
        return Err(format!("{field_name} must not be empty"));
    }
    HeaderValue::from_str(peer_id)
        .map_err(|_| format!("{field_name} must be a valid HTTP header value"))?;
    Ok(peer_id)
}

pub(super) fn decode_peer_key(value: &str) -> Result<[u8; 32], String> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value.as_bytes())
        .map_err(|err| format!("invalid peer_key: {err}"))?;
    let peer_key: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| "invalid peer_key length".to_string())?;
    Ok(peer_key)
}

pub(super) fn control_protocol(value: &str) -> Result<MeshProtocol, String> {
    match value {
        "http" | "https" => Ok(MeshProtocol::Http),
        "tcp" => Ok(MeshProtocol::Tcp),
        _ => Err(format!("unsupported protocol {value}")),
    }
}

pub(super) fn build_inbound_routes(config: &MeshConfig) -> Result<InboundRoutes, RouterError> {
    let mut map = HashMap::new();
    for route in &config.inbound {
        if route.protocol != MeshProtocol::Http && !route.http_plugins.is_empty() {
            return Err(RouterError::InvalidConfig(format!(
                "inbound route {} has http plugins but uses {} protocol",
                route.route_id,
                protocol_string(route.protocol)
            )));
        }
        if !route.http_plugins.is_empty() && !matches!(route.target, InboundTarget::Local { .. }) {
            return Err(RouterError::InvalidConfig(format!(
                "inbound route {} has http plugins but target is not local",
                route.route_id
            )));
        }
        if map.insert(route.route_id.clone(), route.clone()).is_some() {
            return Err(RouterError::InvalidConfig(format!(
                "duplicate inbound route_id {}",
                route.route_id
            )));
        }
    }
    Ok(map)
}

pub(super) fn validate_outbound_routes(config: &MeshConfig) -> Result<(), RouterError> {
    for route in &config.outbound {
        if route.protocol != MeshProtocol::Http && !route.http_plugins.is_empty() {
            return Err(RouterError::InvalidConfig(format!(
                "outbound route {} has http plugins but uses {} protocol",
                route.route_id,
                protocol_string(route.protocol)
            )));
        }
    }
    Ok(())
}

pub(super) fn resolve_inbound_route<'a>(
    inbound_routes: &'a InboundRoutes,
    dynamic_route_overlays: &'a HashMap<String, DynamicRouteOverlay>,
    open: &OpenFrame,
    remote_id: &str,
    dynamic_issuers: &HashMap<String, HashSet<String>>,
) -> Result<&'a InboundRoute, RouterError> {
    let route = inbound_routes
        .get(&open.route_id)
        .or_else(|| {
            dynamic_route_overlays
                .values()
                .find_map(|overlay| overlay.routes.get(&open.route_id))
        })
        .ok_or_else(|| {
            RouterError::Auth(format!(
                "unknown route {} for peer {} capability {} protocol {}",
                open.route_id,
                remote_id,
                open.capability,
                protocol_string(open.protocol)
            ))
        })?;

    if open.capability != route.capability || open.protocol != route.protocol {
        return Err(RouterError::Auth(format!(
            "open frame mismatch for route {} from peer {}: capability {} vs {}, protocol {} vs {}",
            open.route_id,
            remote_id,
            open.capability,
            route.capability,
            protocol_string(open.protocol),
            protocol_string(route.protocol)
        )));
    }

    if !route_allowed(route, remote_id, dynamic_issuers.get(&route.route_id)) {
        return Err(RouterError::Auth(format!(
            "peer {} not allowed for route {}",
            remote_id, open.route_id
        )));
    }

    Ok(route)
}

pub(super) fn route_allowed(
    route: &InboundRoute,
    remote_id: &str,
    dynamic_issuers_for_key: Option<&HashSet<String>>,
) -> bool {
    if route
        .allowed_issuers
        .iter()
        .any(|issuer| issuer == remote_id)
    {
        return true;
    }
    dynamic_issuers_for_key
        .map(|issuers| issuers.contains(remote_id))
        .unwrap_or(false)
}

pub(super) fn resolve_http_plugins(
    route_plugins: &[HttpRoutePlugin],
    a2a_url_rewrite_table: Arc<a2a::UrlRewriteTable>,
) -> Arc<[Arc<dyn HttpExchangePlugin>]> {
    route_plugins
        .iter()
        .copied()
        .map(|plugin| -> Arc<dyn HttpExchangePlugin> {
            match plugin {
                HttpRoutePlugin::A2a => {
                    Arc::new(a2a::A2aUrlRewritePlugin::new(a2a_url_rewrite_table.clone()))
                }
            }
        })
        .collect::<Vec<Arc<dyn HttpExchangePlugin>>>()
        .into()
}

pub(super) fn protocol_string(protocol: MeshProtocol) -> String {
    match protocol {
        MeshProtocol::Http => "http".to_string(),
        MeshProtocol::Tcp => "tcp".to_string(),
    }
}
