use std::{
    collections::{HashMap, HashSet, VecDeque},
    env,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::Arc,
};

use amber_mesh::{
    HttpRoutePlugin, InboundRoute, InboundTarget, MeshConfig, MeshConfigPublic, MeshIdentity,
    MeshIdentityPublic, MeshIdentitySecret, MeshPeer, MeshProtocol, OutboundRoute,
    component_route_id,
};
use base64::Engine as _;
use bytes::Bytes;
use curve25519_dalek::edwards::CompressedEdwardsY;
use futures::StreamExt as _;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri, header};
use http_body_util::{BodyExt as _, BodyStream, Full, StreamBody};
use hyper::{
    body::{Frame, Incoming},
    client::conn::http1 as client_http1,
    server::conn::http1,
    service::service_fn,
};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
    service::TowerToHyperService,
};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use snow::{HandshakeState, TransportState};
use thiserror::Error;
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, duplex, split},
    net::TcpListener,
    sync::{Mutex, RwLock},
    task::JoinSet,
};
use tower::{ServiceBuilder, ServiceExt as _, service_fn as tower_service_fn};
use tower_http::{compression::CompressionLayer, decompression::Decompression};
use url::Url;

mod a2a;

#[derive(Debug, Error)]
pub enum RouterError {
    #[error(
        "missing router config (set AMBER_ROUTER_CONFIG_PATH, AMBER_ROUTER_CONFIG_B64, or \
         AMBER_ROUTER_CONFIG_JSON)"
    )]
    MissingConfig,
    #[error(
        "missing router identity (set AMBER_ROUTER_IDENTITY_PATH or AMBER_ROUTER_IDENTITY_JSON)"
    )]
    MissingIdentity,
    #[error("invalid router config: {0}")]
    InvalidConfig(String),
    #[error("failed to bind {addr}: {source}")]
    BindFailed {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to bind unix socket {path}: {source}")]
    BindUnixFailed {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("mesh handshake failed: {0}")]
    Handshake(String),
    #[error("mesh auth failed: {0}")]
    Auth(String),
    #[error("mesh transport error: {0}")]
    Transport(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct OpenFrame {
    route_id: String,
    capability: String,
    protocol: MeshProtocol,
}

#[derive(Clone)]
struct HttpProxyState {
    client: HttpClient,
    target: ExternalTarget,
}

#[derive(Clone)]
struct LocalHttpProxyState {
    client: HttpClient,
    base_url: Url,
    plugins: Arc<[Arc<dyn HttpExchangePlugin>]>,
    route_id: Arc<str>,
}

#[derive(Clone)]
struct OutboundHttpProxyState {
    upstream: Arc<Mutex<client_http1::SendRequest<BoxBody>>>,
    plugins: Arc<[Arc<dyn HttpExchangePlugin>]>,
    route_id: Arc<str>,
}

type HttpClient = Client<HttpsConnector<HttpConnector>, BoxBody>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BodyMode {
    Stream,
    Collect,
}

#[allow(dead_code)]
enum FilterDecision {
    Continue,
    Reject { status: StatusCode, message: String },
}

struct RewriteContext {
    flow: RewriteFlow,
    request_is_agent_card: bool,
    route_id: Arc<str>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RewriteFlow {
    Inbound,
    Outbound,
}

trait HttpExchangePlugin: Send + Sync {
    fn matches(&self, req: &http::request::Parts) -> bool;

    fn request_body_mode(&self, _req: &http::request::Parts) -> BodyMode {
        BodyMode::Stream
    }

    fn response_body_mode(&self, _req: &http::request::Parts) -> BodyMode {
        BodyMode::Stream
    }

    fn filter_request(
        &self,
        _ctx: &RewriteContext,
        _parts: &http::request::Parts,
        _body: Option<&[u8]>,
    ) -> FilterDecision {
        FilterDecision::Continue
    }

    fn filter_response(
        &self,
        _ctx: &RewriteContext,
        _parts: &http::response::Parts,
        _body: Option<&[u8]>,
    ) -> FilterDecision {
        FilterDecision::Continue
    }

    fn rewrite_request(
        &self,
        _ctx: &RewriteContext,
        _parts: &mut http::request::Parts,
        _body: &mut Vec<u8>,
    ) -> bool {
        false
    }

    fn rewrite_response(
        &self,
        _ctx: &RewriteContext,
        _parts: &mut http::response::Parts,
        _body: &mut Vec<u8>,
    ) -> bool {
        false
    }

    fn request_stream_rewriter(
        &self,
        _ctx: &RewriteContext,
        _parts: &http::request::Parts,
    ) -> Option<Box<dyn StreamBodyRewriter>> {
        None
    }

    fn response_stream_rewriter(
        &self,
        _ctx: &RewriteContext,
        _parts: &http::response::Parts,
    ) -> Option<Box<dyn StreamBodyRewriter>> {
        None
    }
}

trait StreamBodyRewriter: Send + Sync {
    fn rewrite_chunk(&mut self, chunk: &[u8], is_final: bool) -> Vec<u8>;
}

#[derive(Clone, Debug)]
struct ExternalTarget {
    name: String,
    url_env: String,
    optional: bool,
    url_override: Option<String>,
}

#[derive(Clone, Debug)]
struct MeshExternalTarget {
    peer_addr: String,
    peer_id: String,
    peer_key: [u8; 32],
}

type ExternalOverrides = Arc<RwLock<HashMap<String, String>>>;
type ControlAllowlist = Arc<HashSet<IpAddr>>;
type DynamicIssuers = Arc<RwLock<HashMap<String, HashSet<String>>>>;
type InboundRoutes = HashMap<String, InboundRoute>;

#[derive(Clone)]
struct ControlServiceState {
    external_overrides: ExternalOverrides,
    trust: Arc<TrustBundle>,
    inbound_routes: Arc<InboundRoutes>,
    dynamic_issuers: DynamicIssuers,
    identity: MeshIdentityPublic,
}

#[derive(Clone)]
struct InboundRuntime {
    config: Arc<MeshConfig>,
    trust: Arc<TrustBundle>,
    inbound_routes: Arc<InboundRoutes>,
    dynamic_issuers: DynamicIssuers,
    external_overrides: ExternalOverrides,
    client: Arc<HttpClient>,
    a2a_url_rewrite_table: Arc<a2a::UrlRewriteTable>,
}

#[derive(Debug, Deserialize)]
struct ControlExternalSlot {
    url: String,
}

#[derive(Debug, Deserialize)]
struct ControlExportPeer {
    peer_id: String,
    peer_key: String,
    protocol: String,
}

const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const MAX_FRAME: usize = 64 * 1024;
const MAX_PLAINTEXT: usize = 16 * 1024;
const CONTROL_SOCKET_PATH_ENV: &str = "AMBER_ROUTER_CONTROL_SOCKET_PATH";

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

fn parse_config_json(
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

fn load_identity_from_env() -> Result<MeshIdentitySecret, RouterError> {
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

fn parse_identity_json(raw: &str) -> Result<MeshIdentitySecret, RouterError> {
    if raw.trim().is_empty() {
        return Err(RouterError::MissingIdentity);
    }
    serde_json::from_str(raw).map_err(|err| RouterError::InvalidConfig(err.to_string()))
}

pub async fn run(config: MeshConfig) -> Result<(), RouterError> {
    let trust = Arc::new(TrustBundle::new(&config)?);
    let inbound_routes = Arc::new(build_inbound_routes(&config)?);
    validate_outbound_routes(&config)?;
    let a2a_url_rewrite_table = Arc::new(a2a::UrlRewriteTable::from_routes(
        &config.inbound,
        &config.outbound,
    ));
    let dynamic_issuers = Arc::new(RwLock::new(HashMap::new()));
    let identity_public = MeshIdentityPublic::from_identity(&config.identity);
    let control_allow = match config.control_allow.as_ref() {
        Some(entries) => Some(resolve_control_allowlist(entries).await?),
        None => None,
    };
    let config = Arc::new(config);
    let external_overrides = Arc::new(RwLock::new(HashMap::new()));

    let mut listeners = JoinSet::new();

    {
        listeners.spawn(run_mesh_listener(InboundRuntime {
            config: config.clone(),
            trust: trust.clone(),
            inbound_routes: inbound_routes.clone(),
            dynamic_issuers: dynamic_issuers.clone(),
            external_overrides: external_overrides.clone(),
            client: Arc::new(build_client()),
            a2a_url_rewrite_table: a2a_url_rewrite_table.clone(),
        }));
    }

    for route in config.outbound.clone() {
        let config = config.clone();
        let trust = trust.clone();
        let a2a_url_rewrite_table = a2a_url_rewrite_table.clone();
        listeners.spawn(run_outbound_listener(
            route,
            config,
            trust,
            a2a_url_rewrite_table,
        ));
    }

    let control_socket_path = env::var(CONTROL_SOCKET_PATH_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    if let Some(path) = control_socket_path.clone() {
        #[cfg(unix)]
        {
            let external_overrides = external_overrides.clone();
            let trust = trust.clone();
            let inbound_routes = inbound_routes.clone();
            let dynamic_issuers = dynamic_issuers.clone();
            let identity_public = identity_public.clone();
            listeners.spawn(run_control_server_unix(
                path,
                external_overrides,
                trust,
                inbound_routes,
                dynamic_issuers,
                identity_public,
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
        let external_overrides = external_overrides.clone();
        let control_allow = control_allow.clone();
        let trust = trust.clone();
        let inbound_routes = inbound_routes.clone();
        let dynamic_issuers = dynamic_issuers.clone();
        let identity_public = identity_public.clone();
        listeners.spawn(run_control_server(
            addr,
            external_overrides,
            control_allow,
            trust,
            inbound_routes,
            dynamic_issuers,
            identity_public,
        ));
    }

    let Some(listener) = listeners.join_next().await else {
        return Err(RouterError::Transport(
            "no listener tasks were started".to_string(),
        ));
    };

    listeners.abort_all();
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

async fn run_mesh_listener(state: InboundRuntime) -> Result<(), RouterError> {
    let listener = TcpListener::bind(state.config.mesh_listen)
        .await
        .map_err(|source| RouterError::BindFailed {
            addr: state.config.mesh_listen,
            source,
        })?;

    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_inbound(stream, state).await {
                tracing::warn!("mesh connection failed: {err}");
            }
        });
    }
}

async fn handle_inbound(
    stream: tokio::net::TcpStream,
    state: InboundRuntime,
) -> Result<(), RouterError> {
    let InboundRuntime {
        config,
        trust,
        inbound_routes,
        dynamic_issuers,
        external_overrides,
        client,
        a2a_url_rewrite_table,
    } = state;
    let noise_keys = noise_keys_for_identity(&config.identity)?;
    let mut session = accept_noise(stream, &noise_keys, &trust).await?;
    let remote_id = session
        .remote_id
        .clone()
        .ok_or_else(|| RouterError::Auth("unknown peer".to_string()))?;
    let open = session.recv_open().await?;
    let route = {
        let issuers = dynamic_issuers.read().await;
        resolve_inbound_route(inbound_routes.as_ref(), &open, &remote_id, &issuers)?.clone()
    };

    match route.target {
        InboundTarget::Local { port } => {
            if route.protocol == MeshProtocol::Http {
                let plugins = resolve_http_plugins(&route.http_plugins, a2a_url_rewrite_table);
                if plugins.is_empty() {
                    let target = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
                    proxy_noise_to_plain(&mut session, target).await?;
                } else {
                    proxy_noise_to_local_http(
                        &mut session,
                        route.route_id.clone().into(),
                        port,
                        client.clone(),
                        plugins,
                    )
                    .await?;
                }
            } else {
                let target = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
                proxy_noise_to_plain(&mut session, target).await?;
            }
        }
        InboundTarget::External { url_env, optional } => {
            let override_url = {
                let overrides = external_overrides.read().await;
                overrides.get(&route.capability).cloned()
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

                return proxy_by_external_protocol(
                    &mut session,
                    route.protocol,
                    ExternalTarget {
                        name: route.capability.clone(),
                        url_env,
                        optional,
                        url_override: Some(override_url),
                    },
                    client.clone(),
                )
                .await;
            }

            if let Ok(raw) = env::var(&url_env) {
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

            proxy_by_external_protocol(
                &mut session,
                route.protocol,
                ExternalTarget {
                    name: route.capability.clone(),
                    url_env,
                    optional,
                    url_override: None,
                },
                client.clone(),
            )
            .await?;
        }
        InboundTarget::MeshForward {
            peer_addr,
            peer_id,
            route_id,
            capability,
        } => {
            let outbound = connect_noise(&peer_addr, &peer_id, &config, &trust).await?;
            let open = OpenFrame {
                route_id,
                capability,
                protocol: route.protocol,
            };
            outbound.send_open(&open).await?;
            proxy_noise_to_noise(&mut session, outbound).await?;
        }
    }

    Ok(())
}

async fn maybe_proxy_mesh_external(
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
        route_id: component_route_id(&mesh.peer_id, capability, protocol),
        capability: capability.to_string(),
        protocol,
    };
    outbound.send_open(&open).await?;
    proxy_noise_to_noise(session, outbound).await?;
    Ok(true)
}

async fn proxy_by_external_protocol(
    session: &mut NoiseSession,
    protocol: MeshProtocol,
    target: ExternalTarget,
    client: Arc<HttpClient>,
) -> Result<(), RouterError> {
    match protocol {
        MeshProtocol::Http => proxy_noise_to_external(session, target, client).await,
        MeshProtocol::Tcp => proxy_noise_to_external_tcp(session, target).await,
    }
}

async fn run_outbound_listener(
    route: OutboundRoute,
    config: Arc<MeshConfig>,
    trust: Arc<TrustBundle>,
    a2a_url_rewrite_table: Arc<a2a::UrlRewriteTable>,
) -> Result<(), RouterError> {
    let listen_ip = route
        .listen_addr
        .as_deref()
        .unwrap_or("127.0.0.1")
        .parse()
        .map_err(|_| RouterError::InvalidConfig("invalid listen address".to_string()))?;
    let listen_addr = SocketAddr::new(listen_ip, route.listen_port);
    let listener =
        TcpListener::bind(listen_addr)
            .await
            .map_err(|source| RouterError::BindFailed {
                addr: listen_addr,
                source,
            })?;

    loop {
        let (stream, _) = listener.accept().await?;
        let route = route.clone();
        let config = config.clone();
        let trust = trust.clone();
        let a2a_url_rewrite_table = a2a_url_rewrite_table.clone();
        tokio::spawn(async move {
            if let Err(err) =
                handle_outbound(stream, route, config, trust, a2a_url_rewrite_table).await
            {
                tracing::warn!("outbound connection failed: {err}");
            }
        });
    }
}

async fn handle_outbound(
    stream: tokio::net::TcpStream,
    route: OutboundRoute,
    config: Arc<MeshConfig>,
    trust: Arc<TrustBundle>,
    a2a_url_rewrite_table: Arc<a2a::UrlRewriteTable>,
) -> Result<(), RouterError> {
    let mut outbound = connect_noise(&route.peer_addr, &route.peer_id, &config, &trust).await?;

    let open = OpenFrame {
        route_id: route.route_id.clone(),
        capability: route.capability.clone(),
        protocol: route.protocol,
    };
    outbound.send_open(&open).await?;
    if route.protocol == MeshProtocol::Http && !route.http_plugins.is_empty() {
        let plugins = resolve_http_plugins(&route.http_plugins, a2a_url_rewrite_table);
        proxy_local_http_to_noise(
            &mut outbound,
            route.route_id.clone().into(),
            stream,
            plugins,
        )
        .await?;
    } else {
        proxy_noise_to_plain(&mut outbound, stream).await?;
    }

    Ok(())
}

async fn run_control_server(
    addr: SocketAddr,
    external_overrides: ExternalOverrides,
    control_allow: Option<ControlAllowlist>,
    trust: Arc<TrustBundle>,
    inbound_routes: Arc<InboundRoutes>,
    dynamic_issuers: DynamicIssuers,
    identity: MeshIdentityPublic,
) -> Result<(), RouterError> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|source| RouterError::BindFailed { addr, source })?;
    let state = ControlServiceState {
        external_overrides,
        trust,
        inbound_routes,
        dynamic_issuers,
        identity,
    };

    loop {
        let (stream, peer) = listener.accept().await?;
        let control_allow = control_allow.clone();
        let state = state.clone();
        tokio::spawn(async move {
            let allowed = control_allow
                .as_ref()
                .is_none_or(|allow| allow.contains(&peer.ip()));
            if let Err(err) = serve_control_connection(stream, state, allowed).await {
                tracing::warn!("control connection failed: {err}");
            }
        });
    }
}

#[cfg(unix)]
async fn run_control_server_unix(
    path: String,
    external_overrides: ExternalOverrides,
    trust: Arc<TrustBundle>,
    inbound_routes: Arc<InboundRoutes>,
    dynamic_issuers: DynamicIssuers,
    identity: MeshIdentityPublic,
) -> Result<(), RouterError> {
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
    let state = ControlServiceState {
        external_overrides,
        trust,
        inbound_routes,
        dynamic_issuers,
        identity,
    };

    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = serve_control_connection(stream, state, true).await {
                tracing::warn!("control unix connection failed: {err}");
            }
        });
    }
}

async fn serve_control_connection<IO>(
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
                dynamic_issuers,
                identity,
            } = state;
            control_service(
                req,
                external_overrides,
                trust,
                inbound_routes,
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

async fn resolve_control_allowlist(entries: &[String]) -> Result<ControlAllowlist, RouterError> {
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

async fn control_service(
    req: Request<Incoming>,
    external_overrides: ExternalOverrides,
    trust: Arc<TrustBundle>,
    inbound_routes: Arc<InboundRoutes>,
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
                    &dynamic_issuers,
                    &identity.id,
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
    }
}

enum ControlRoute<'a> {
    Identity,
    ExternalSlot(&'a str),
    Export(&'a str),
}

fn control_route(path: &str) -> Option<ControlRoute<'_>> {
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
        _ => None,
    }
}

fn control_empty(status: StatusCode) -> Response<BoxBody> {
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

fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Response<BoxBody> {
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

async fn register_export_peer(
    export: &str,
    payload: ControlExportPeer,
    trust: &TrustBundle,
    inbound_routes: &InboundRoutes,
    dynamic_issuers: &DynamicIssuers,
    router_id: &str,
) -> Result<(), String> {
    let peer_id = payload.peer_id.trim();
    if peer_id.is_empty() {
        return Err("peer_id must not be empty".to_string());
    }
    if peer_id == router_id {
        return Err("peer_id must not be the router identity".to_string());
    }
    let peer_key = decode_peer_key(&payload.peer_key)?;
    let protocol = control_protocol(payload.protocol.trim())?;
    let mut export_routes = inbound_routes.values().filter(|route| {
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

fn decode_peer_key(value: &str) -> Result<[u8; 32], String> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value.as_bytes())
        .map_err(|err| format!("invalid peer_key: {err}"))?;
    let peer_key: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| "invalid peer_key length".to_string())?;
    Ok(peer_key)
}

fn control_protocol(value: &str) -> Result<MeshProtocol, String> {
    match value {
        "http" | "https" => Ok(MeshProtocol::Http),
        "tcp" => Ok(MeshProtocol::Tcp),
        _ => Err(format!("unsupported protocol {value}")),
    }
}

fn build_inbound_routes(config: &MeshConfig) -> Result<InboundRoutes, RouterError> {
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

fn validate_outbound_routes(config: &MeshConfig) -> Result<(), RouterError> {
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

fn resolve_inbound_route<'a>(
    inbound_routes: &'a InboundRoutes,
    open: &OpenFrame,
    remote_id: &str,
    dynamic_issuers: &HashMap<String, HashSet<String>>,
) -> Result<&'a InboundRoute, RouterError> {
    let route = inbound_routes
        .get(&open.route_id)
        .ok_or_else(|| RouterError::Auth("unknown route".to_string()))?;

    if open.capability != route.capability || open.protocol != route.protocol {
        return Err(RouterError::Auth("open frame mismatch".to_string()));
    }

    if !route_allowed(route, remote_id, dynamic_issuers.get(&route.route_id)) {
        return Err(RouterError::Auth("peer not allowed".to_string()));
    }

    Ok(route)
}

fn route_allowed(
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
    if !matches!(route.target, InboundTarget::MeshForward { .. }) {
        return false;
    }
    dynamic_issuers_for_key
        .map(|issuers| issuers.contains(remote_id))
        .unwrap_or(false)
}

fn resolve_http_plugins(
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

fn protocol_string(protocol: MeshProtocol) -> String {
    match protocol {
        MeshProtocol::Http => "http".to_string(),
        MeshProtocol::Tcp => "tcp".to_string(),
    }
}

#[derive(Clone)]
struct NoiseSession {
    state: Arc<Mutex<TransportState>>,
    reader: Arc<Mutex<tokio::net::tcp::OwnedReadHalf>>,
    writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    remote_id: Option<String>,
}

impl NoiseSession {
    async fn send_open(&self, open: &OpenFrame) -> Result<(), RouterError> {
        let bytes =
            serde_json::to_vec(open).map_err(|err| RouterError::Transport(err.to_string()))?;
        self.send_plain(&bytes).await
    }

    async fn recv_open(&mut self) -> Result<OpenFrame, RouterError> {
        let bytes = self
            .recv_plain()
            .await?
            .ok_or_else(|| RouterError::Transport("missing open frame".to_string()))?;
        serde_json::from_slice(&bytes).map_err(|err| RouterError::Transport(err.to_string()))
    }

    async fn send_plain(&self, data: &[u8]) -> Result<(), RouterError> {
        if data.len() > MAX_FRAME {
            return Err(RouterError::Transport("frame too large".to_string()));
        }
        let mut out = vec![0u8; data.len() + 128];
        let len = {
            let mut state = self.state.lock().await;
            state
                .write_message(data, &mut out)
                .map_err(|err| RouterError::Transport(err.to_string()))?
        };
        let mut writer = self.writer.lock().await;
        write_frame(&mut writer, &out[..len]).await?;
        Ok(())
    }

    async fn recv_plain(&self) -> Result<Option<Vec<u8>>, RouterError> {
        let frame = {
            let mut reader = self.reader.lock().await;
            read_frame(&mut reader).await?
        };
        let Some(frame) = frame else {
            return Ok(None);
        };
        let mut buf = vec![0u8; MAX_FRAME];
        let len = {
            let mut state = self.state.lock().await;
            state
                .read_message(&frame, &mut buf)
                .map_err(|err| RouterError::Transport(err.to_string()))?
        };
        buf.truncate(len);
        Ok(Some(buf))
    }

    async fn shutdown(&self) {
        let mut writer = self.writer.lock().await;
        let _ = writer.shutdown().await;
    }
}

async fn accept_noise(
    stream: tokio::net::TcpStream,
    keys: &NoiseKeys,
    trust: &TrustBundle,
) -> Result<NoiseSession, RouterError> {
    let (mut reader, mut writer) = stream.into_split();
    let mut builder = snow::Builder::new(NOISE_PATTERN.parse().unwrap());
    builder = builder.local_private_key(&keys.private);
    let handshake = builder
        .build_responder()
        .map_err(|err| RouterError::Handshake(err.to_string()))?;

    let handshake = perform_handshake(handshake, &mut reader, &mut writer).await?;
    let remote_static = handshake
        .remote_static
        .ok_or_else(|| RouterError::Handshake("missing remote static".to_string()))?;
    let remote_id = trust.id_for_noise_key(&remote_static).await;

    Ok(NoiseSession {
        state: Arc::new(Mutex::new(handshake.transport)),
        reader: Arc::new(Mutex::new(reader)),
        writer: Arc::new(Mutex::new(writer)),
        remote_id,
    })
}

async fn connect_noise(
    peer_addr: &str,
    peer_id: &str,
    config: &MeshConfig,
    trust: &TrustBundle,
) -> Result<NoiseSession, RouterError> {
    let remote = trust
        .noise_key(peer_id)
        .await
        .ok_or_else(|| RouterError::Auth(format!("unknown peer {peer_id}")))?;
    connect_noise_with_remote_key(peer_addr, peer_id, remote, config).await
}

async fn connect_noise_with_key(
    peer_addr: &str,
    peer_id: &str,
    peer_key: [u8; 32],
    config: &MeshConfig,
) -> Result<NoiseSession, RouterError> {
    let remote = ed25519_public_to_x25519(peer_key)?;
    connect_noise_with_remote_key(peer_addr, peer_id, remote, config).await
}

async fn connect_noise_with_remote_key(
    peer_addr: &str,
    peer_id: &str,
    remote: [u8; 32],
    config: &MeshConfig,
) -> Result<NoiseSession, RouterError> {
    let noise_keys = noise_keys_for_identity(&config.identity)?;
    let stream = tokio::net::TcpStream::connect(peer_addr).await?;
    let (mut reader, mut writer) = stream.into_split();

    let mut builder = snow::Builder::new(NOISE_PATTERN.parse().unwrap());
    builder = builder
        .local_private_key(&noise_keys.private)
        .remote_public_key(&remote);
    let handshake = builder
        .build_initiator()
        .map_err(|err| RouterError::Handshake(err.to_string()))?;

    let handshake = perform_handshake(handshake, &mut reader, &mut writer).await?;

    Ok(NoiseSession {
        state: Arc::new(Mutex::new(handshake.transport)),
        reader: Arc::new(Mutex::new(reader)),
        writer: Arc::new(Mutex::new(writer)),
        remote_id: Some(peer_id.to_string()),
    })
}

struct HandshakeResult {
    transport: TransportState,
    remote_static: Option<[u8; 32]>,
}

async fn perform_handshake(
    mut handshake: HandshakeState,
    reader: &mut tokio::net::tcp::OwnedReadHalf,
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
) -> Result<HandshakeResult, RouterError> {
    let mut in_buf = vec![0u8; MAX_FRAME];
    let mut out_buf = vec![0u8; MAX_FRAME];

    while !handshake.is_handshake_finished() {
        if handshake.is_initiator() {
            let len = handshake
                .write_message(&[], &mut out_buf)
                .map_err(|err| RouterError::Handshake(err.to_string()))?;
            write_frame(writer, &out_buf[..len]).await?;
            if handshake.is_handshake_finished() {
                break;
            }
            let frame = read_frame(reader).await?;
            let frame = frame.ok_or_else(|| RouterError::Handshake("handshake EOF".to_string()))?;
            let _ = handshake
                .read_message(&frame, &mut in_buf)
                .map_err(|err| RouterError::Handshake(err.to_string()))?;
        } else {
            let frame = read_frame(reader).await?;
            let frame = frame.ok_or_else(|| RouterError::Handshake("handshake EOF".to_string()))?;
            let _ = handshake
                .read_message(&frame, &mut in_buf)
                .map_err(|err| RouterError::Handshake(err.to_string()))?;
            if handshake.is_handshake_finished() {
                break;
            }
            let len = handshake
                .write_message(&[], &mut out_buf)
                .map_err(|err| RouterError::Handshake(err.to_string()))?;
            write_frame(writer, &out_buf[..len]).await?;
        }
    }

    let remote_static = handshake.get_remote_static().map(|key| {
        let mut out = [0u8; 32];
        out.copy_from_slice(key);
        out
    });
    let transport = handshake
        .into_transport_mode()
        .map_err(|err| RouterError::Handshake(err.to_string()))?;
    Ok(HandshakeResult {
        transport,
        remote_static,
    })
}

async fn read_frame(
    reader: &mut tokio::net::tcp::OwnedReadHalf,
) -> Result<Option<Vec<u8>>, RouterError> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(RouterError::Transport("frame too large".to_string()));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

async fn write_frame(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    data: &[u8],
) -> Result<(), RouterError> {
    let len = u32::try_from(data.len())
        .map_err(|_| RouterError::Transport("frame too large".to_string()))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

async fn proxy_noise_to_plain<S>(session: &mut NoiseSession, plain: S) -> Result<(), RouterError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut plain_reader, mut plain_writer) = split(plain);
    let session_in = session.clone();
    let session_out = session.clone();

    let to_plain = tokio::spawn(async move {
        while let Some(bytes) = session_in.recv_plain().await? {
            plain_writer.write_all(&bytes).await?;
        }
        let _ = plain_writer.shutdown().await;
        Ok::<(), RouterError>(())
    });

    let to_noise = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_PLAINTEXT];
        loop {
            let n = plain_reader.read(&mut buf).await?;
            if n == 0 {
                session_out.shutdown().await;
                break;
            }
            session_out.send_plain(&buf[..n]).await?;
        }
        Ok::<(), RouterError>(())
    });

    let (left, right) = tokio::join!(to_plain, to_noise);
    left.map_err(|err| RouterError::Transport(err.to_string()))??;
    right.map_err(|err| RouterError::Transport(err.to_string()))??;
    Ok(())
}

async fn proxy_noise_to_noise(
    left: &mut NoiseSession,
    right: NoiseSession,
) -> Result<(), RouterError> {
    let left_in = left.clone();
    let left_out = left.clone();
    let right_in = right.clone();
    let right_out = right.clone();

    let to_right = tokio::spawn(async move {
        while let Some(bytes) = left_in.recv_plain().await? {
            right_out.send_plain(&bytes).await?;
        }
        right_out.shutdown().await;
        Ok::<(), RouterError>(())
    });

    let to_left = tokio::spawn(async move {
        while let Some(bytes) = right_in.recv_plain().await? {
            left_out.send_plain(&bytes).await?;
        }
        left_out.shutdown().await;
        Ok::<(), RouterError>(())
    });

    let (left, right) = tokio::join!(to_right, to_left);
    left.map_err(|err| RouterError::Transport(err.to_string()))??;
    right.map_err(|err| RouterError::Transport(err.to_string()))??;
    Ok(())
}

async fn proxy_noise_to_external(
    session: &mut NoiseSession,
    target: ExternalTarget,
    client: Arc<HttpClient>,
) -> Result<(), RouterError> {
    let (local, remote) = duplex(64 * 1024);
    let mut noise_session = session.clone();

    let bridge = tokio::spawn(async move { proxy_noise_to_plain(&mut noise_session, local).await });

    let state = HttpProxyState {
        client: (*client).clone(),
        target,
    };

    let service = service_fn(move |req: Request<Incoming>| {
        let state = state.clone();
        async move { Ok::<_, std::convert::Infallible>(proxy_http_request(state, req).await) }
    });

    if let Err(err) = hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(remote), service)
        .await
    {
        return Err(RouterError::Transport(err.to_string()));
    }

    let _ = bridge.await;
    Ok(())
}

async fn proxy_noise_to_external_tcp(
    session: &mut NoiseSession,
    target: ExternalTarget,
) -> Result<(), RouterError> {
    let (host, port) = resolve_tcp_target(&target)?;
    let upstream = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
    proxy_noise_to_plain(session, upstream).await
}

async fn proxy_noise_to_local_http(
    session: &mut NoiseSession,
    route_id: Arc<str>,
    port: u16,
    client: Arc<HttpClient>,
    plugins: Arc<[Arc<dyn HttpExchangePlugin>]>,
) -> Result<(), RouterError> {
    let (local, remote) = duplex(64 * 1024);
    let mut noise_session = session.clone();

    let bridge = tokio::spawn(async move { proxy_noise_to_plain(&mut noise_session, local).await });

    let base_url = Url::parse(&format!("http://127.0.0.1:{port}"))
        .map_err(|err| RouterError::InvalidConfig(format!("invalid local http target: {err}")))?;
    let state = LocalHttpProxyState {
        client: (*client).clone(),
        base_url,
        plugins,
        route_id,
    };

    let service =
        ServiceBuilder::new()
            .layer(CompressionLayer::new())
            .service(tower_service_fn(move |req| {
                let state = state.clone();
                async move {
                    Ok::<_, std::convert::Infallible>(proxy_local_http_request(state, req).await)
                }
            }));
    let service = TowerToHyperService::new(service);

    if let Err(err) = hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(remote), service)
        .await
    {
        return Err(RouterError::Transport(err.to_string()));
    }

    let _ = bridge.await;
    Ok(())
}

async fn proxy_local_http_request(
    state: LocalHttpProxyState,
    req: Request<Incoming>,
) -> Response<BoxBody> {
    let request_is_agent_card = a2a::is_agent_card_path(req.uri().path());
    let mut parts = req.into_parts();
    let matching_plugins: Vec<&dyn HttpExchangePlugin> = state
        .plugins
        .iter()
        .map(Arc::as_ref)
        .filter(|plugin| plugin.matches(&parts.0))
        .collect();
    let request_body_collect = matching_plugins
        .iter()
        .any(|plugin| plugin.request_body_mode(&parts.0) == BodyMode::Collect);
    let response_body_collect = matching_plugins
        .iter()
        .any(|plugin| plugin.response_body_mode(&parts.0) == BodyMode::Collect);
    let ctx = RewriteContext {
        flow: RewriteFlow::Inbound,
        request_is_agent_card,
        route_id: state.route_id.clone(),
    };
    let request_stream_rewriters = if request_body_collect {
        Vec::new()
    } else {
        collect_request_stream_rewriters(&matching_plugins, &ctx, &parts.0)
    };

    let request_body = if request_body_collect {
        if !is_identity_or_absent_content_encoding(&parts.0.headers) {
            return error_response(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported Content-Encoding on request body",
            );
        }
        let mut body = match parts.1.collect().await {
            Ok(collected) => collected.to_bytes().to_vec(),
            Err(err) => {
                tracing::warn!("router request body read failed: {err}");
                return error_response(StatusCode::BAD_GATEWAY, "upstream request read failed");
            }
        };
        if let Some(response) =
            apply_request_filters(&matching_plugins, &ctx, &parts.0, Some(body.as_slice()))
        {
            return response;
        }

        let mut rewritten = false;
        for plugin in &matching_plugins {
            rewritten |= plugin.rewrite_request(&ctx, &mut parts.0, &mut body);
        }
        if rewritten {
            strip_request_body_validators(&mut parts.0.headers);
        }
        parts
            .0
            .headers
            .insert(header::CONTENT_LENGTH, content_length_header(body.len()));
        Full::new(Bytes::from(body))
            .map_err(|never| match never {})
            .boxed()
    } else {
        if let Some(response) = apply_request_filters(&matching_plugins, &ctx, &parts.0, None) {
            return response;
        }
        if request_stream_rewriters.is_empty() {
            parts.1.boxed()
        } else {
            if !is_identity_or_absent_content_encoding(&parts.0.headers) {
                return error_response(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "unsupported Content-Encoding on request body",
                );
            }
            strip_request_body_validators(&mut parts.0.headers);
            parts.0.headers.remove(header::CONTENT_LENGTH);
            rewrite_stream_body(parts.1, request_stream_rewriters)
        }
    };

    let target_url = join_url(&state.base_url, &parts.0.uri);
    let Some(host) = target_url.host_str() else {
        return error_response(StatusCode::BAD_GATEWAY, "target url missing host");
    };

    let host_header = match target_url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };

    let mut request_parts = parts.0;
    request_parts.uri = match Uri::try_from(target_url.as_str()) {
        Ok(uri) => uri,
        Err(_) => return error_response(StatusCode::BAD_GATEWAY, "invalid target url"),
    };

    if !response_body_collect && !matching_plugins.is_empty() {
        request_parts.headers.remove(header::ACCEPT_ENCODING);
    }
    sanitize_request_headers(&mut request_parts.headers, &host_header);

    let proxied = Request::from_parts(request_parts, request_body);
    if response_body_collect {
        let response = match Decompression::new(state.client.clone())
            .oneshot(proxied)
            .await
        {
            Ok(resp) => resp,
            Err(err) => {
                tracing::warn!("router request failed: {err}");
                return error_response(StatusCode::BAD_GATEWAY, "upstream request failed");
            }
        };
        let (mut response_parts, response_body) = response.into_parts();
        let mut body = match response_body.collect().await {
            Ok(collected) => collected.to_bytes().to_vec(),
            Err(err) => {
                tracing::warn!("router response body read failed: {err}");
                return error_response(StatusCode::BAD_GATEWAY, "upstream response read failed");
            }
        };
        if let Some(response) = apply_response_filters(
            &matching_plugins,
            &ctx,
            &response_parts,
            Some(body.as_slice()),
        ) {
            return response;
        }

        let mut rewritten = false;
        for plugin in &matching_plugins {
            rewritten |= plugin.rewrite_response(&ctx, &mut response_parts, &mut body);
        }

        sanitize_response_headers(&mut response_parts.headers);
        if rewritten {
            strip_response_body_validators(&mut response_parts.headers);
        }
        response_parts
            .headers
            .insert(header::CONTENT_LENGTH, content_length_header(body.len()));
        return Response::from_parts(
            response_parts,
            Full::new(Bytes::from(body))
                .map_err(|never| match never {})
                .boxed(),
        );
    }

    let response = match state.client.request(proxied).await {
        Ok(resp) => resp,
        Err(err) => {
            tracing::warn!("router request failed: {err}");
            return error_response(StatusCode::BAD_GATEWAY, "upstream request failed");
        }
    };
    let (mut response_parts, response_body) = response.into_parts();
    if let Some(response) = apply_response_filters(&matching_plugins, &ctx, &response_parts, None) {
        return response;
    }
    let response_stream_rewriters =
        collect_response_stream_rewriters(&matching_plugins, &ctx, &response_parts);
    let response_body = if !response_stream_rewriters.is_empty()
        && is_identity_or_absent_content_encoding(&response_parts.headers)
    {
        strip_response_body_validators(&mut response_parts.headers);
        response_parts.headers.remove(header::CONTENT_LENGTH);
        rewrite_stream_body(response_body, response_stream_rewriters)
    } else {
        response_body.boxed()
    };
    sanitize_response_headers(&mut response_parts.headers);
    Response::from_parts(response_parts, response_body)
}

async fn proxy_local_http_to_noise(
    session: &mut NoiseSession,
    route_id: Arc<str>,
    stream: tokio::net::TcpStream,
    plugins: Arc<[Arc<dyn HttpExchangePlugin>]>,
) -> Result<(), RouterError> {
    let (local, remote) = duplex(64 * 1024);
    let mut noise_session = session.clone();

    let bridge =
        tokio::spawn(async move { proxy_noise_to_plain(&mut noise_session, remote).await });

    let (sender, conn) = client_http1::handshake(TokioIo::new(local))
        .await
        .map_err(|err| {
            RouterError::Transport(format!("outbound upstream handshake failed: {err}"))
        })?;
    let conn_task = tokio::spawn(async move {
        if let Err(err) = conn.await {
            tracing::warn!("outbound upstream connection failed: {err}");
        }
    });

    let state = OutboundHttpProxyState {
        upstream: Arc::new(Mutex::new(sender)),
        plugins,
        route_id,
    };

    let service = ServiceBuilder::new()
        .layer(CompressionLayer::new())
        .service(tower_service_fn(move |req| {
            let state = state.clone();
            async move {
                Ok::<_, std::convert::Infallible>(proxy_outbound_http_request(state, req).await)
            }
        }));
    let service = TowerToHyperService::new(service);

    if let Err(err) = hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .await
    {
        return Err(RouterError::Transport(err.to_string()));
    }

    let _ = conn_task.await;
    let _ = bridge.await;
    Ok(())
}

async fn proxy_outbound_http_request(
    state: OutboundHttpProxyState,
    req: Request<Incoming>,
) -> Response<BoxBody> {
    let request_is_agent_card = a2a::is_agent_card_path(req.uri().path());
    let mut parts = req.into_parts();
    let matching_plugins: Vec<&dyn HttpExchangePlugin> = state
        .plugins
        .iter()
        .map(Arc::as_ref)
        .filter(|plugin| plugin.matches(&parts.0))
        .collect();
    let request_body_collect = matching_plugins
        .iter()
        .any(|plugin| plugin.request_body_mode(&parts.0) == BodyMode::Collect);
    let response_body_collect = matching_plugins
        .iter()
        .any(|plugin| plugin.response_body_mode(&parts.0) == BodyMode::Collect);
    let ctx = RewriteContext {
        flow: RewriteFlow::Outbound,
        request_is_agent_card,
        route_id: state.route_id.clone(),
    };
    let request_stream_rewriters = if request_body_collect {
        Vec::new()
    } else {
        collect_request_stream_rewriters(&matching_plugins, &ctx, &parts.0)
    };

    let request_body = if request_body_collect {
        if !is_identity_or_absent_content_encoding(&parts.0.headers) {
            return error_response(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported Content-Encoding on request body",
            );
        }
        let mut body = match parts.1.collect().await {
            Ok(collected) => collected.to_bytes().to_vec(),
            Err(err) => {
                tracing::warn!("router request body read failed: {err}");
                return error_response(StatusCode::BAD_GATEWAY, "upstream request read failed");
            }
        };
        if let Some(response) =
            apply_request_filters(&matching_plugins, &ctx, &parts.0, Some(body.as_slice()))
        {
            return response;
        }

        let mut rewritten = false;
        for plugin in &matching_plugins {
            rewritten |= plugin.rewrite_request(&ctx, &mut parts.0, &mut body);
        }
        if rewritten {
            strip_request_body_validators(&mut parts.0.headers);
        }
        parts
            .0
            .headers
            .insert(header::CONTENT_LENGTH, content_length_header(body.len()));
        Full::new(Bytes::from(body))
            .map_err(|never| match never {})
            .boxed()
    } else {
        if let Some(response) = apply_request_filters(&matching_plugins, &ctx, &parts.0, None) {
            return response;
        }
        if request_stream_rewriters.is_empty() {
            parts.1.boxed()
        } else {
            if !is_identity_or_absent_content_encoding(&parts.0.headers) {
                return error_response(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "unsupported Content-Encoding on request body",
                );
            }
            strip_request_body_validators(&mut parts.0.headers);
            parts.0.headers.remove(header::CONTENT_LENGTH);
            rewrite_stream_body(parts.1, request_stream_rewriters)
        }
    };

    let mut request_parts = parts.0;
    if response_body_collect || !matching_plugins.is_empty() {
        request_parts.headers.remove(header::ACCEPT_ENCODING);
    }
    let host_header = outgoing_host_header(&request_parts.uri, &request_parts.headers);
    sanitize_request_headers(&mut request_parts.headers, host_header.as_str());

    let proxied = Request::from_parts(request_parts, request_body);
    let response = {
        let mut upstream = state.upstream.lock().await;
        match upstream.send_request(proxied).await {
            Ok(resp) => resp,
            Err(err) => {
                tracing::warn!("router request failed: {err}");
                return error_response(StatusCode::BAD_GATEWAY, "upstream request failed");
            }
        }
    };

    if response_body_collect {
        let (mut response_parts, response_body) = response.into_parts();
        let mut body = match response_body.collect().await {
            Ok(collected) => collected.to_bytes().to_vec(),
            Err(err) => {
                tracing::warn!("router response body read failed: {err}");
                return error_response(StatusCode::BAD_GATEWAY, "upstream response read failed");
            }
        };
        if let Some(response) = apply_response_filters(
            &matching_plugins,
            &ctx,
            &response_parts,
            Some(body.as_slice()),
        ) {
            return response;
        }

        let mut rewritten = false;
        for plugin in &matching_plugins {
            rewritten |= plugin.rewrite_response(&ctx, &mut response_parts, &mut body);
        }

        sanitize_response_headers(&mut response_parts.headers);
        if rewritten {
            strip_response_body_validators(&mut response_parts.headers);
        }
        response_parts
            .headers
            .insert(header::CONTENT_LENGTH, content_length_header(body.len()));
        return Response::from_parts(
            response_parts,
            Full::new(Bytes::from(body))
                .map_err(|never| match never {})
                .boxed(),
        );
    }

    let (mut response_parts, response_body) = response.into_parts();
    if let Some(response) = apply_response_filters(&matching_plugins, &ctx, &response_parts, None) {
        return response;
    }
    let response_stream_rewriters =
        collect_response_stream_rewriters(&matching_plugins, &ctx, &response_parts);
    let response_body = if !response_stream_rewriters.is_empty()
        && is_identity_or_absent_content_encoding(&response_parts.headers)
    {
        strip_response_body_validators(&mut response_parts.headers);
        response_parts.headers.remove(header::CONTENT_LENGTH);
        rewrite_stream_body(response_body, response_stream_rewriters)
    } else {
        response_body.boxed()
    };
    sanitize_response_headers(&mut response_parts.headers);
    Response::from_parts(response_parts, response_body)
}

async fn proxy_http_request(state: HttpProxyState, req: Request<Incoming>) -> Response<BoxBody> {
    let target_url = match resolve_target_url(&state.target, &req) {
        Ok(url) => url,
        Err(err) => return err,
    };

    let mut parts = req.into_parts();
    let Some(host) = target_url.host_str() else {
        return error_response(StatusCode::BAD_GATEWAY, "target url missing host");
    };

    let host_header = match target_url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };

    parts.0.uri = match Uri::try_from(target_url.as_str()) {
        Ok(uri) => uri,
        Err(_) => return error_response(StatusCode::BAD_GATEWAY, "invalid target url"),
    };

    sanitize_request_headers(&mut parts.0.headers, &host_header);

    let proxied = Request::from_parts(parts.0, parts.1.boxed());

    let response = match state.client.request(proxied).await {
        Ok(resp) => resp,
        Err(err) => {
            tracing::warn!("router request failed: {err}");
            return error_response(StatusCode::BAD_GATEWAY, "upstream request failed");
        }
    };

    let mut parts = response.into_parts();
    sanitize_response_headers(&mut parts.0.headers);
    let body = parts.1.boxed();
    Response::from_parts(parts.0, body)
}

fn outgoing_host_header(uri: &Uri, headers: &HeaderMap) -> String {
    uri.authority()
        .map(|value| value.as_str().trim().to_string())
        .or_else(|| {
            headers
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.trim().to_string())
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "localhost".to_string())
}

fn strip_request_body_validators(headers: &mut HeaderMap) {
    headers.remove(http::header::HeaderName::from_static("content-md5"));
    headers.remove(http::header::HeaderName::from_static("digest"));
}

fn strip_response_body_validators(headers: &mut HeaderMap) {
    headers.remove(header::ETAG);
    headers.remove(header::LAST_MODIFIED);
    headers.remove(http::header::HeaderName::from_static("content-md5"));
    headers.remove(http::header::HeaderName::from_static("digest"));
}

fn content_length_header(length: usize) -> HeaderValue {
    HeaderValue::from_str(&length.to_string()).unwrap_or_else(|_| HeaderValue::from_static("0"))
}

fn collect_request_stream_rewriters(
    plugins: &[&dyn HttpExchangePlugin],
    ctx: &RewriteContext,
    parts: &http::request::Parts,
) -> Vec<Box<dyn StreamBodyRewriter>> {
    plugins
        .iter()
        .filter_map(|plugin| plugin.request_stream_rewriter(ctx, parts))
        .collect()
}

fn collect_response_stream_rewriters(
    plugins: &[&dyn HttpExchangePlugin],
    ctx: &RewriteContext,
    parts: &http::response::Parts,
) -> Vec<Box<dyn StreamBodyRewriter>> {
    plugins
        .iter()
        .filter_map(|plugin| plugin.response_stream_rewriter(ctx, parts))
        .collect()
}

fn is_identity_or_absent_content_encoding(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .map(|raw| {
            raw.split(',').all(|item| {
                let encoding = item.split(';').next().unwrap_or("").trim();
                encoding.is_empty() || encoding.eq_ignore_ascii_case("identity")
            })
        })
        .unwrap_or(true)
}

fn rewrite_stream_body(body: Incoming, rewriters: Vec<Box<dyn StreamBodyRewriter>>) -> BoxBody {
    let stream = futures::stream::try_unfold(
        (
            BodyStream::new(body),
            rewriters,
            false,
            false,
            VecDeque::<Frame<Bytes>>::new(),
        ),
        |(mut source, mut rewriters, mut finished, mut rewriting_complete, mut queue)| async move {
            loop {
                if let Some(frame) = queue.pop_front() {
                    return Ok(Some((
                        frame,
                        (source, rewriters, finished, rewriting_complete, queue),
                    )));
                }

                if finished {
                    return Ok(None);
                }

                match source.next().await {
                    Some(Ok(frame)) => match frame.into_data() {
                        Ok(chunk) => {
                            if rewriting_complete {
                                queue.push_back(Frame::data(chunk));
                                continue;
                            }

                            let mut rewritten = chunk.to_vec();
                            for rewriter in &mut rewriters {
                                rewritten = rewriter.rewrite_chunk(rewritten.as_slice(), false);
                            }
                            if rewritten.is_empty() {
                                continue;
                            }
                            queue.push_back(Frame::data(Bytes::from(rewritten)));
                        }
                        Err(frame) => {
                            if !rewriting_complete {
                                let mut flushed = Vec::new();
                                for rewriter in &mut rewriters {
                                    flushed = rewriter.rewrite_chunk(flushed.as_slice(), true);
                                }
                                if !flushed.is_empty() {
                                    queue.push_back(Frame::data(Bytes::from(flushed)));
                                }
                                rewriting_complete = true;
                            }
                            queue.push_back(frame);
                        }
                    },
                    Some(Err(err)) => return Err(err),
                    None => {
                        finished = true;
                        if rewriting_complete {
                            continue;
                        }

                        let mut flushed = Vec::new();
                        for rewriter in &mut rewriters {
                            flushed = rewriter.rewrite_chunk(flushed.as_slice(), true);
                        }
                        if !flushed.is_empty() {
                            queue.push_back(Frame::data(Bytes::from(flushed)));
                        }
                        rewriting_complete = true;
                    }
                }
            }
        },
    );

    http_body_util::BodyExt::map_err(StreamBody::new(stream), |err| err).boxed()
}

fn apply_request_filters(
    plugins: &[&dyn HttpExchangePlugin],
    ctx: &RewriteContext,
    parts: &http::request::Parts,
    body: Option<&[u8]>,
) -> Option<Response<BoxBody>> {
    for plugin in plugins {
        match plugin.filter_request(ctx, parts, body) {
            FilterDecision::Continue => {}
            FilterDecision::Reject { status, message } => {
                return Some(error_response(status, &message));
            }
        }
    }
    None
}

fn apply_response_filters(
    plugins: &[&dyn HttpExchangePlugin],
    ctx: &RewriteContext,
    parts: &http::response::Parts,
    body: Option<&[u8]>,
) -> Option<Response<BoxBody>> {
    for plugin in plugins {
        match plugin.filter_response(ctx, parts, body) {
            FilterDecision::Continue => {}
            FilterDecision::Reject { status, message } => {
                return Some(error_response(status, &message));
            }
        }
    }
    None
}

type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

#[allow(clippy::result_large_err)]
fn resolve_target_url(
    target: &ExternalTarget,
    req: &Request<Incoming>,
) -> Result<Url, Response<BoxBody>> {
    let url = match target.url_override.clone() {
        Some(value) if !value.trim().is_empty() => value,
        _ => match env::var(&target.url_env) {
            Ok(value) if !value.trim().is_empty() => value,
            _ => {
                let message = if target.optional {
                    format!(
                        "external slot {} is optional and not configured",
                        target.name
                    )
                } else {
                    format!("external slot {} is not configured", target.name)
                };
                return Err(error_response(StatusCode::SERVICE_UNAVAILABLE, &message));
            }
        },
    };

    let base = Url::parse(&url)
        .map_err(|_| error_response(StatusCode::BAD_GATEWAY, "external slot url is invalid"))?;

    if !is_http_scheme(&base) {
        return Err(error_response(
            StatusCode::BAD_GATEWAY,
            "external slot url must be http/https",
        ));
    }

    Ok(join_url(&base, req.uri()))
}

fn resolve_tcp_target(target: &ExternalTarget) -> Result<(String, u16), RouterError> {
    let url = match target.url_override.as_ref() {
        Some(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => match env::var(&target.url_env) {
            Ok(value) if !value.trim().is_empty() => value.trim().to_string(),
            _ => {
                let message = if target.optional {
                    format!(
                        "external slot {} is optional and not configured",
                        target.name
                    )
                } else {
                    format!("external slot {} is not configured", target.name)
                };
                return Err(RouterError::InvalidConfig(message));
            }
        },
    };

    let parsed = Url::parse(&url).map_err(|err| {
        RouterError::InvalidConfig(format!("external slot url is invalid: {err}"))
    })?;
    if parsed.scheme() != "tcp" {
        return Err(RouterError::InvalidConfig(
            "external tcp target url must use tcp://".to_string(),
        ));
    }
    let host = parsed.host_str().ok_or_else(|| {
        RouterError::InvalidConfig("external tcp target url missing host".to_string())
    })?;
    let port = parsed.port().ok_or_else(|| {
        RouterError::InvalidConfig("external tcp target url missing port".to_string())
    })?;

    Ok((host.to_string(), port))
}

fn join_url(base: &Url, uri: &Uri) -> Url {
    let mut out = base.clone();
    out.set_path(&join_paths(base.path(), uri.path()));
    if out.query().is_none() {
        out.set_query(uri.query());
    }
    out
}

fn join_paths(base: &str, req: &str) -> String {
    let base = base.trim_end_matches('/');
    let req = req.trim_start_matches('/');

    let joined = if base.is_empty() {
        if req.is_empty() {
            "/".to_string()
        } else {
            format!("/{req}")
        }
    } else if req.is_empty() {
        base.to_string()
    } else {
        format!("{base}/{req}")
    };

    if joined.starts_with('/') {
        joined
    } else {
        format!("/{joined}")
    }
}

fn is_http_scheme(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
}

fn parse_mesh_external(value: &str) -> Result<MeshExternalTarget, RouterError> {
    let url = Url::parse(value)
        .map_err(|err| RouterError::InvalidConfig(format!("invalid mesh url: {err}")))?;
    if url.scheme() != "mesh" {
        return Err(RouterError::InvalidConfig(
            "mesh url must use mesh:// scheme".to_string(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| RouterError::InvalidConfig("mesh url missing host".to_string()))?;
    let port = url
        .port()
        .ok_or_else(|| RouterError::InvalidConfig("mesh url missing port".to_string()))?;

    let mut peer_id = None;
    let mut peer_key = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "peer_id" => peer_id = Some(value.to_string()),
            "peer_key" => peer_key = Some(value.to_string()),
            _ => {}
        }
    }
    let peer_id = peer_id
        .ok_or_else(|| RouterError::InvalidConfig("mesh url missing peer_id".to_string()))?;
    let peer_key = peer_key
        .ok_or_else(|| RouterError::InvalidConfig("mesh url missing peer_key".to_string()))?;
    let peer_key = decode_peer_key(&peer_key).map_err(RouterError::InvalidConfig)?;

    Ok(MeshExternalTarget {
        peer_addr: format!("{host}:{port}"),
        peer_id,
        peer_key,
    })
}

fn error_response(status: StatusCode, message: &str) -> Response<BoxBody> {
    let body = Full::new(Bytes::from(message.to_string()))
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(body)
        .unwrap_or_else(|_| {
            Response::new(
                Full::new(Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
        })
}

fn sanitize_request_headers(headers: &mut HeaderMap, host_header: &str) {
    headers.remove(header::HOST);
    headers.insert(
        header::HOST,
        HeaderValue::from_str(host_header).unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    strip_hop_by_hop(headers);
}

fn sanitize_response_headers(headers: &mut HeaderMap) {
    strip_hop_by_hop(headers);
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    for name in [
        header::CONNECTION,
        header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHORIZATION,
        header::TE,
        header::TRAILER,
        header::TRANSFER_ENCODING,
        header::UPGRADE,
    ] {
        headers.remove(name);
    }
}

fn build_client() -> HttpClient {
    install_default_crypto_provider();
    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    Client::builder(TokioExecutor::new()).build(https)
}

fn install_default_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

#[derive(Clone, Debug)]
struct NoiseKeys {
    private: [u8; 32],
}

fn noise_keys_for_identity(identity: &MeshIdentity) -> Result<NoiseKeys, RouterError> {
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&identity.private_key[..32]);
    let private = ed25519_seed_to_x25519(seed);
    Ok(NoiseKeys { private })
}

fn ed25519_seed_to_x25519(seed: [u8; 32]) -> [u8; 32] {
    let hash = sha2::Sha512::digest(seed);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash[..32]);
    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;
    out
}

fn ed25519_public_to_x25519(public: [u8; 32]) -> Result<[u8; 32], RouterError> {
    let compressed = CompressedEdwardsY(public);
    let point = compressed
        .decompress()
        .ok_or_else(|| RouterError::Auth("invalid public key".to_string()))?;
    Ok(point.to_montgomery().to_bytes())
}

struct TrustBundle {
    inner: RwLock<TrustState>,
}

struct TrustState {
    noise_by_id: HashMap<String, [u8; 32]>,
    id_by_noise: HashMap<[u8; 32], String>,
}

impl TrustBundle {
    fn new(config: &MeshConfig) -> Result<Self, RouterError> {
        let mut noise_by_id = HashMap::new();
        let mut id_by_noise = HashMap::new();

        for peer in &config.peers {
            insert_peer(peer, &mut noise_by_id, &mut id_by_noise)?;
        }

        Ok(Self {
            inner: RwLock::new(TrustState {
                noise_by_id,
                id_by_noise,
            }),
        })
    }

    async fn noise_key(&self, id: &str) -> Option<[u8; 32]> {
        let inner = self.inner.read().await;
        inner.noise_by_id.get(id).copied()
    }

    async fn id_for_noise_key(&self, key: &[u8; 32]) -> Option<String> {
        let inner = self.inner.read().await;
        inner.id_by_noise.get(key).cloned()
    }

    async fn insert_peer(&self, peer: &MeshPeer) -> Result<(), RouterError> {
        let noise = ed25519_public_to_x25519(peer.public_key)?;
        let mut inner = self.inner.write().await;
        if let Some(existing) = inner.noise_by_id.get(&peer.id).copied() {
            if existing == noise {
                return Ok(());
            }
            return Err(RouterError::Auth(format!(
                "peer {} already registered with a different key",
                peer.id
            )));
        }
        if let Some(existing_id) = inner.id_by_noise.get(&noise)
            && existing_id != &peer.id
        {
            return Err(RouterError::Auth(format!(
                "peer key already registered for {}",
                existing_id
            )));
        }
        inner.noise_by_id.insert(peer.id.clone(), noise);
        inner.id_by_noise.insert(noise, peer.id.clone());
        Ok(())
    }
}

fn insert_peer(
    peer: &MeshPeer,
    noise_by_id: &mut HashMap<String, [u8; 32]>,
    id_by_noise: &mut HashMap<[u8; 32], String>,
) -> Result<(), RouterError> {
    let noise = ed25519_public_to_x25519(peer.public_key)?;
    noise_by_id.insert(peer.id.clone(), noise);
    id_by_noise.insert(noise, peer.id.clone());
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use base64::Engine as _;

    use super::*;

    fn test_mesh_config() -> MeshConfig {
        MeshConfig {
            identity: MeshIdentity::generate("router", Some("test-scope".to_string())),
            mesh_listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            control_listen: None,
            control_allow: None,
            peers: Vec::new(),
            inbound: Vec::new(),
            outbound: Vec::new(),
            transport: amber_mesh::TransportConfig::NoiseIk {},
        }
    }

    fn test_peer(id: &str) -> MeshPeer {
        let identity = MeshIdentity::generate(id, Some("test-scope".to_string()));
        MeshPeer {
            id: id.to_string(),
            public_key: identity.public_key,
        }
    }

    fn inbound_route(
        route_id: &str,
        capability: &str,
        protocol: MeshProtocol,
        target: InboundTarget,
        allowed_issuers: &[&str],
    ) -> InboundRoute {
        InboundRoute {
            route_id: route_id.to_string(),
            capability: capability.to_string(),
            protocol,
            http_plugins: Vec::new(),
            target,
            allowed_issuers: allowed_issuers.iter().map(ToString::to_string).collect(),
        }
    }

    #[test]
    fn build_inbound_routes_rejects_duplicate_route_id() {
        let config = MeshConfig {
            inbound: vec![
                inbound_route(
                    "dup",
                    "shared-a",
                    MeshProtocol::Http,
                    InboundTarget::Local { port: 7001 },
                    &["peer-a"],
                ),
                inbound_route(
                    "dup",
                    "shared-b",
                    MeshProtocol::Http,
                    InboundTarget::Local { port: 7002 },
                    &["peer-b"],
                ),
            ],
            ..test_mesh_config()
        };

        let err = build_inbound_routes(&config).expect_err("duplicate route id should fail");
        match err {
            RouterError::InvalidConfig(message) => {
                assert!(message.contains("duplicate inbound route_id dup"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn build_inbound_routes_rejects_http_plugins_on_non_http_route() {
        let config = MeshConfig {
            inbound: vec![InboundRoute {
                route_id: "bad-route".to_string(),
                capability: "cap".to_string(),
                protocol: MeshProtocol::Tcp,
                http_plugins: vec![HttpRoutePlugin::A2a],
                target: InboundTarget::Local { port: 7001 },
                allowed_issuers: vec!["peer-a".to_string()],
            }],
            ..test_mesh_config()
        };

        let err =
            build_inbound_routes(&config).expect_err("non-http route with http plugin should fail");
        match err {
            RouterError::InvalidConfig(message) => {
                assert!(message.contains("has http plugins but uses tcp protocol"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn build_inbound_routes_rejects_http_plugins_on_non_local_target() {
        let config = MeshConfig {
            inbound: vec![InboundRoute {
                route_id: "bad-route".to_string(),
                capability: "cap".to_string(),
                protocol: MeshProtocol::Http,
                http_plugins: vec![HttpRoutePlugin::A2a],
                target: InboundTarget::External {
                    url_env: "TEST_URL".to_string(),
                    optional: false,
                },
                allowed_issuers: vec!["peer-a".to_string()],
            }],
            ..test_mesh_config()
        };

        let err = build_inbound_routes(&config)
            .expect_err("non-local target with http plugin should fail");
        match err {
            RouterError::InvalidConfig(message) => {
                assert!(message.contains("has http plugins but target is not local"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn validate_outbound_routes_rejects_http_plugins_on_non_http_route() {
        let config = MeshConfig {
            outbound: vec![OutboundRoute {
                route_id: "bad-route".to_string(),
                slot: "slot".to_string(),
                listen_port: 20000,
                listen_addr: None,
                protocol: MeshProtocol::Tcp,
                http_plugins: vec![HttpRoutePlugin::A2a],
                peer_addr: "127.0.0.1:30000".to_string(),
                peer_id: "peer-a".to_string(),
                capability: "cap".to_string(),
            }],
            ..test_mesh_config()
        };

        let err = validate_outbound_routes(&config)
            .expect_err("non-http outbound route with http plugin should fail");
        match err {
            RouterError::InvalidConfig(message) => {
                assert!(message.contains("has http plugins but uses tcp protocol"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn join_paths_handles_root() {
        assert_eq!(join_paths("/", "/foo"), "/foo");
        assert_eq!(join_paths("", "/foo"), "/foo");
        assert_eq!(join_paths("/", "/"), "/");
    }

    #[test]
    fn join_paths_preserves_base_prefix() {
        assert_eq!(join_paths("/v1", "/chat"), "/v1/chat");
        assert_eq!(join_paths("/v1/", "/chat"), "/v1/chat");
        assert_eq!(join_paths("/v1", "/"), "/v1");
    }

    #[test]
    fn join_url_copies_request_query_when_base_has_none() {
        let base = Url::parse("http://example.com/v1").expect("base url");
        let uri: Uri = "/chat?model=gpt".parse().expect("request uri");
        let out = join_url(&base, &uri);
        assert_eq!(out.as_str(), "http://example.com/v1/chat?model=gpt");
    }

    #[test]
    fn join_url_preserves_base_query_over_request_query() {
        let base = Url::parse("http://example.com/v1?token=abc").expect("base url");
        let uri: Uri = "/chat?model=gpt".parse().expect("request uri");
        let out = join_url(&base, &uri);
        assert_eq!(out.as_str(), "http://example.com/v1/chat?token=abc");
    }

    #[test]
    fn join_url_preserves_empty_base_query() {
        let base = Url::parse("http://example.com/v1?").expect("base url");
        let uri: Uri = "/chat?model=gpt".parse().expect("request uri");
        let out = join_url(&base, &uri);
        assert_eq!(out.path(), "/v1/chat");
        assert_eq!(out.query(), Some(""));
    }

    #[tokio::test]
    async fn insert_peer_allows_idempotent_same_key() {
        let trust = TrustBundle::new(&test_mesh_config()).expect("trust bundle");
        let peer = test_peer("dynamic-peer");
        trust.insert_peer(&peer).await.expect("first insert");
        trust.insert_peer(&peer).await.expect("second insert");
    }

    #[tokio::test]
    async fn insert_peer_rejects_existing_id_with_different_key() {
        let trust = TrustBundle::new(&test_mesh_config()).expect("trust bundle");
        let first = test_peer("dynamic-peer");
        let second = test_peer("dynamic-peer");
        trust.insert_peer(&first).await.expect("first insert");
        let err = trust
            .insert_peer(&second)
            .await
            .expect_err("second insert should fail");
        match err {
            RouterError::Auth(message) => {
                assert!(message.contains("different key"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[tokio::test]
    async fn insert_peer_rejects_key_reused_by_different_id() {
        let trust = TrustBundle::new(&test_mesh_config()).expect("trust bundle");
        let identity = MeshIdentity::generate("first-peer", Some("test-scope".to_string()));
        let first = MeshPeer {
            id: "first-peer".to_string(),
            public_key: identity.public_key,
        };
        let second = MeshPeer {
            id: "second-peer".to_string(),
            public_key: identity.public_key,
        };
        trust.insert_peer(&first).await.expect("first insert");
        let err = trust
            .insert_peer(&second)
            .await
            .expect_err("second insert should fail");
        match err {
            RouterError::Auth(message) => {
                assert!(message.contains("peer key already registered for first-peer"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[tokio::test]
    async fn run_surfaces_outbound_listener_bind_failure() {
        let occupied = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind occupied listener");
        let occupied_addr = occupied
            .local_addr()
            .expect("read occupied listener address");

        let mut config = test_mesh_config();
        config.outbound.push(amber_mesh::OutboundRoute {
            route_id: "route".to_string(),
            slot: "test-outbound".to_string(),
            listen_port: occupied_addr.port(),
            listen_addr: Some("127.0.0.1".to_string()),
            protocol: MeshProtocol::Tcp,
            http_plugins: Vec::new(),
            peer_addr: "127.0.0.1:65535".to_string(),
            peer_id: "peer".to_string(),
            capability: "capability".to_string(),
        });

        let err = tokio::time::timeout(Duration::from_secs(2), run(config))
            .await
            .expect("run should return when a listener fails to bind")
            .expect_err("run should fail when outbound listener port is occupied");

        match err {
            RouterError::BindFailed { addr, .. } => assert_eq!(addr, occupied_addr),
            other => panic!("expected bind failure, got {other}"),
        }
    }

    #[test]
    fn resolve_inbound_route_isolated_by_peer_identity() {
        let config = MeshConfig {
            inbound: vec![
                inbound_route(
                    "route-a",
                    "shared",
                    MeshProtocol::Http,
                    InboundTarget::Local { port: 7001 },
                    &["peer-a"],
                ),
                inbound_route(
                    "route-b",
                    "shared",
                    MeshProtocol::Http,
                    InboundTarget::Local { port: 7002 },
                    &["peer-b"],
                ),
            ],
            ..test_mesh_config()
        };
        let inbound_routes = build_inbound_routes(&config).expect("build inbound routes");
        let open = OpenFrame {
            route_id: "route-a".to_string(),
            capability: "shared".to_string(),
            protocol: MeshProtocol::Http,
        };

        let a = resolve_inbound_route(&inbound_routes, &open, "peer-a", &HashMap::new())
            .expect("peer-a route should resolve");
        let denied = resolve_inbound_route(&inbound_routes, &open, "peer-b", &HashMap::new())
            .expect_err("peer-c should not be allowed");

        match &a.target {
            InboundTarget::Local { port } => assert_eq!(*port, 7001),
            _ => panic!("peer-a should resolve to local route"),
        }
        match denied {
            RouterError::Auth(message) => assert_eq!(message, "peer not allowed"),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn resolve_inbound_route_rejects_route_id_spoof() {
        let config = MeshConfig {
            inbound: vec![
                inbound_route(
                    "route-a",
                    "shared",
                    MeshProtocol::Http,
                    InboundTarget::Local { port: 7001 },
                    &["peer-a"],
                ),
                inbound_route(
                    "route-b",
                    "shared",
                    MeshProtocol::Http,
                    InboundTarget::Local { port: 7002 },
                    &["peer-b"],
                ),
            ],
            ..test_mesh_config()
        };
        let inbound_routes = build_inbound_routes(&config).expect("build inbound routes");
        let spoofed = OpenFrame {
            route_id: "route-b".to_string(),
            capability: "shared".to_string(),
            protocol: MeshProtocol::Http,
        };
        let denied = resolve_inbound_route(&inbound_routes, &spoofed, "peer-a", &HashMap::new())
            .expect_err("peer-a should not be able to use peer-b route id");
        match denied {
            RouterError::Auth(message) => assert_eq!(message, "peer not allowed"),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn resolve_inbound_route_dynamic_issuers_apply_only_to_exports() {
        let config = MeshConfig {
            inbound: vec![
                inbound_route(
                    "external-route",
                    "shared",
                    MeshProtocol::Http,
                    InboundTarget::External {
                        url_env: "SHARED_URL".to_string(),
                        optional: false,
                    },
                    &["consumer"],
                ),
                inbound_route(
                    "export-route",
                    "shared",
                    MeshProtocol::Http,
                    InboundTarget::MeshForward {
                        peer_addr: "127.0.0.1:1234".to_string(),
                        peer_id: "provider".to_string(),
                        route_id: "provider-route".to_string(),
                        capability: "upstream".to_string(),
                    },
                    &["router"],
                ),
            ],
            ..test_mesh_config()
        };
        let inbound_routes = build_inbound_routes(&config).expect("build inbound routes");
        let open = OpenFrame {
            route_id: "export-route".to_string(),
            capability: "shared".to_string(),
            protocol: MeshProtocol::Http,
        };
        let dynamic = HashSet::from([String::from("dynamic-peer")]);
        let issuers = HashMap::from([(String::from("export-route"), dynamic.clone())]);

        let dynamic_route = resolve_inbound_route(&inbound_routes, &open, "dynamic-peer", &issuers)
            .expect("dynamic issuer should resolve");
        let denied = resolve_inbound_route(&inbound_routes, &open, "consumer", &HashMap::new())
            .expect_err("consumer should not be authorized for export route");

        assert!(
            matches!(&dynamic_route.target, InboundTarget::MeshForward { .. }),
            "dynamic issuers must only authorize mesh-forward exports"
        );
        match denied {
            RouterError::Auth(message) => assert_eq!(message, "peer not allowed"),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[tokio::test]
    async fn register_export_peer_succeeds_when_export_key_collides_with_external_slot() {
        let mut config = test_mesh_config();
        config.inbound = vec![
            inbound_route(
                "export-route",
                "shared",
                MeshProtocol::Http,
                InboundTarget::MeshForward {
                    peer_addr: "127.0.0.1:1234".to_string(),
                    peer_id: "provider".to_string(),
                    route_id: "provider-route".to_string(),
                    capability: "upstream".to_string(),
                },
                &[config.identity.id.as_str()],
            ),
            inbound_route(
                "external-route",
                "shared",
                MeshProtocol::Http,
                InboundTarget::External {
                    url_env: "SHARED_URL".to_string(),
                    optional: false,
                },
                &["consumer"],
            ),
        ];
        let inbound_routes = build_inbound_routes(&config).expect("build inbound routes");
        let trust = TrustBundle::new(&config).expect("trust");
        let dynamic_issuers: DynamicIssuers = Arc::new(RwLock::new(HashMap::new()));
        let peer = test_peer("dynamic-peer");
        let payload = ControlExportPeer {
            peer_id: peer.id.clone(),
            peer_key: base64::engine::general_purpose::STANDARD.encode(peer.public_key),
            protocol: "http".to_string(),
        };

        register_export_peer(
            "shared",
            payload,
            &trust,
            &inbound_routes,
            &dynamic_issuers,
            &config.identity.id,
        )
        .await
        .expect("export registration should succeed");

        let issuers = dynamic_issuers.read().await;
        assert!(
            issuers
                .get("export-route")
                .is_some_and(|ids| ids.contains("dynamic-peer")),
            "dynamic issuer should be registered under the export key"
        );
    }
}
