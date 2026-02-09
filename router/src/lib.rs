use std::{
    collections::{HashMap, HashSet},
    env,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use amber_mesh::{
    InboundRoute, InboundTarget, MeshConfig, MeshConfigPublic, MeshIdentity, MeshIdentitySecret,
    MeshPeer, MeshProtocol,
};
use base64::Engine as _;
use bytes::Bytes;
use curve25519_dalek::edwards::CompressedEdwardsY;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri, header};
use http_body_util::{BodyExt as _, Full};
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
};
use serde::Deserialize;
use sha2::Digest as _;
use snow::{HandshakeState, TransportState};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, duplex, split},
    net::TcpListener,
    sync::{Mutex, RwLock},
};
use url::Url;

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
    capability: String,
    protocol: MeshProtocol,
}

#[derive(Clone)]
struct HttpProxyState {
    client: HttpClient,
    target: ExternalTarget,
}

type HttpClient = Client<HttpsConnector<HttpConnector>, Incoming>;

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

#[derive(Debug, Deserialize)]
struct ControlExternalSlot {
    url: String,
}

const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const MAX_FRAME: usize = 64 * 1024;
const MAX_PLAINTEXT: usize = 16 * 1024;

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
    validate_config(&config)?;
    let trust = Arc::new(TrustBundle::new(&config)?);
    let inbound_routes = Arc::new(build_inbound_routes(&config));
    let control_allow = match config.control_allow.as_ref() {
        Some(entries) => Some(resolve_control_allowlist(entries).await?),
        None => None,
    };
    let config = Arc::new(config);
    let external_overrides = Arc::new(RwLock::new(HashMap::new()));

    let mut handles = Vec::new();

    let mesh_handle = {
        let config = config.clone();
        let trust = trust.clone();
        let inbound_routes = inbound_routes.clone();
        let external_overrides = external_overrides.clone();
        let client = Arc::new(build_client());
        tokio::spawn(async move {
            if let Err(err) =
                run_mesh_listener(config, trust, inbound_routes, external_overrides, client).await
            {
                eprintln!("mesh listener failed: {err}");
            }
        })
    };
    handles.push(mesh_handle);

    for route in config.outbound.clone() {
        let config = config.clone();
        let trust = trust.clone();
        let handle = tokio::spawn(async move {
            if let Err(err) = run_outbound_listener(route, config, trust).await {
                eprintln!("outbound listener failed: {err}");
            }
        });
        handles.push(handle);
    }

    if let Some(addr) = config.control_listen {
        let external_overrides = external_overrides.clone();
        let control_allow = control_allow.clone();
        let handle = tokio::spawn(async move {
            if let Err(err) = run_control_server(addr, external_overrides, control_allow).await {
                eprintln!("control listener failed: {err}");
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}

fn validate_config(config: &MeshConfig) -> Result<(), RouterError> {
    for route in &config.inbound {
        if route.protocol == MeshProtocol::Udp {
            return Err(RouterError::InvalidConfig(format!(
                "udp protocol not supported for inbound capability {}",
                route.capability
            )));
        }
    }
    for route in &config.outbound {
        if route.protocol == MeshProtocol::Udp {
            return Err(RouterError::InvalidConfig(format!(
                "udp protocol not supported for outbound slot {}",
                route.slot
            )));
        }
    }
    Ok(())
}

async fn run_mesh_listener(
    config: Arc<MeshConfig>,
    trust: Arc<TrustBundle>,
    inbound_routes: Arc<HashMap<String, InboundRoute>>,
    external_overrides: ExternalOverrides,
    client: Arc<HttpClient>,
) -> Result<(), RouterError> {
    let listener = TcpListener::bind(config.mesh_listen)
        .await
        .map_err(|source| RouterError::BindFailed {
            addr: config.mesh_listen,
            source,
        })?;

    loop {
        let (stream, _) = listener.accept().await?;
        let config = config.clone();
        let trust = trust.clone();
        let inbound_routes = inbound_routes.clone();
        let external_overrides = external_overrides.clone();
        let client = client.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_inbound(
                stream,
                config,
                trust,
                inbound_routes,
                external_overrides,
                client,
            )
            .await
            {
                eprintln!("mesh connection failed: {err}");
            }
        });
    }
}

async fn handle_inbound(
    stream: tokio::net::TcpStream,
    config: Arc<MeshConfig>,
    trust: Arc<TrustBundle>,
    inbound_routes: Arc<HashMap<String, InboundRoute>>,
    external_overrides: ExternalOverrides,
    client: Arc<HttpClient>,
) -> Result<(), RouterError> {
    let noise_keys = noise_keys_for_identity(&config.identity)?;
    let mut session = accept_noise(stream, &noise_keys, &trust).await?;
    let open = session.recv_open().await?;
    let key = inbound_key(&open.capability, open.protocol);
    let route = inbound_routes
        .get(&key)
        .ok_or_else(|| RouterError::Auth("unknown capability".to_string()))?
        .clone();

    if open.capability != route.capability || open.protocol != route.protocol {
        return Err(RouterError::Auth("open frame mismatch".to_string()));
    }

    let remote_id = session
        .remote_id
        .clone()
        .ok_or_else(|| RouterError::Auth("unknown peer".to_string()))?;
    if !route.allowed_issuers.contains(&remote_id) {
        return Err(RouterError::Auth("peer not allowed".to_string()));
    }

    match route.target {
        InboundTarget::Local { port } => {
            let target = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
            proxy_noise_to_plain(&mut session, target).await?;
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
                if override_url.starts_with("mesh://") {
                    let mesh = parse_mesh_external(&override_url)?;
                    let outbound = connect_noise_with_key(
                        &mesh.peer_addr,
                        &mesh.peer_id,
                        mesh.peer_key,
                        &config,
                    )
                    .await?;
                    let open = OpenFrame {
                        capability: route.capability.clone(),
                        protocol: route.protocol,
                    };
                    outbound.send_open(&open).await?;
                    proxy_noise_to_noise(&mut session, outbound).await?;
                    return Ok(());
                }

                if route.protocol != MeshProtocol::Http {
                    return Err(RouterError::InvalidConfig(
                        "external targets require http protocol".to_string(),
                    ));
                }
                let target = ExternalTarget {
                    name: route.capability.clone(),
                    url_env,
                    optional,
                    url_override: Some(override_url),
                };
                proxy_noise_to_external(&mut session, target, client).await?;
                return Ok(());
            }

            if let Ok(raw) = env::var(&url_env) {
                let trimmed = raw.trim();
                if trimmed.starts_with("mesh://") {
                    let mesh = parse_mesh_external(trimmed)?;
                    let outbound = connect_noise_with_key(
                        &mesh.peer_addr,
                        &mesh.peer_id,
                        mesh.peer_key,
                        &config,
                    )
                    .await?;
                    let open = OpenFrame {
                        capability: route.capability.clone(),
                        protocol: route.protocol,
                    };
                    outbound.send_open(&open).await?;
                    proxy_noise_to_noise(&mut session, outbound).await?;
                    return Ok(());
                }
            }

            if route.protocol != MeshProtocol::Http {
                return Err(RouterError::InvalidConfig(
                    "external targets require http protocol".to_string(),
                ));
            }
            let target = ExternalTarget {
                name: route.capability.clone(),
                url_env,
                optional,
                url_override: None,
            };
            proxy_noise_to_external(&mut session, target, client).await?;
        }
        InboundTarget::MeshForward {
            peer_addr,
            peer_id,
            capability,
        } => {
            let outbound = connect_noise(&peer_addr, &peer_id, &config, &trust).await?;
            let open = OpenFrame {
                capability,
                protocol: route.protocol,
            };
            outbound.send_open(&open).await?;
            proxy_noise_to_noise(&mut session, outbound).await?;
        }
    }

    Ok(())
}

async fn run_outbound_listener(
    route: amber_mesh::OutboundRoute,
    config: Arc<MeshConfig>,
    trust: Arc<TrustBundle>,
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
        tokio::spawn(async move {
            if let Err(err) = handle_outbound(stream, route, config, trust).await {
                eprintln!("outbound connection failed: {err}");
            }
        });
    }
}

async fn handle_outbound(
    stream: tokio::net::TcpStream,
    route: amber_mesh::OutboundRoute,
    config: Arc<MeshConfig>,
    trust: Arc<TrustBundle>,
) -> Result<(), RouterError> {
    let mut outbound = connect_noise(&route.peer_addr, &route.peer_id, &config, &trust).await?;

    let open = OpenFrame {
        capability: route.capability,
        protocol: route.protocol,
    };
    outbound.send_open(&open).await?;
    proxy_noise_to_plain(&mut outbound, stream).await?;

    Ok(())
}

async fn run_control_server(
    addr: SocketAddr,
    external_overrides: ExternalOverrides,
    control_allow: Option<ControlAllowlist>,
) -> Result<(), RouterError> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|source| RouterError::BindFailed { addr, source })?;

    loop {
        let (stream, peer) = listener.accept().await?;
        let external_overrides = external_overrides.clone();
        let control_allow = control_allow.clone();
        tokio::spawn(async move {
            let allowed = match control_allow.as_ref() {
                Some(allow) => allow.contains(&peer.ip()),
                None => true,
            };
            let service = service_fn(move |req| {
                let external_overrides = external_overrides.clone();
                async move {
                    if allowed {
                        control_service(req, external_overrides).await
                    } else {
                        Ok(error_response(
                            StatusCode::FORBIDDEN,
                            "control access denied",
                        ))
                    }
                }
            });
            if let Err(err) = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                eprintln!("control connection failed: {err}");
            }
        });
    }
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
) -> Result<Response<BoxBody>, hyper::Error> {
    let path = req.uri().path().to_string();
    let Some(slot) = control_slot_name(&path) else {
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            "unknown control route",
        ));
    };

    match *req.method() {
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
    }
}

fn control_slot_name(path: &str) -> Option<&str> {
    let mut parts = path.trim_matches('/').split('/');
    let prefix = parts.next()?;
    if prefix != "external-slots" {
        return None;
    }
    let slot = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    Some(slot)
}

fn control_empty(status: StatusCode) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_LENGTH, "0")
        .body(Full::new(Bytes::new()).map_err(|err| match err {}).boxed())
        .unwrap_or_else(|_| {
            Response::new(Full::new(Bytes::new()).map_err(|err| match err {}).boxed())
        })
}

fn build_inbound_routes(config: &MeshConfig) -> HashMap<String, InboundRoute> {
    let mut map = HashMap::new();
    for route in &config.inbound {
        let key = inbound_key(&route.capability, route.protocol);
        map.insert(key, route.clone());
    }
    map
}

fn inbound_key(capability: &str, protocol: MeshProtocol) -> String {
    format!("{capability}::{}", protocol_string(protocol))
}

fn protocol_string(protocol: MeshProtocol) -> String {
    match protocol {
        MeshProtocol::Http => "http".to_string(),
        MeshProtocol::Tcp => "tcp".to_string(),
        MeshProtocol::Udp => "udp".to_string(),
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
    let remote_id = trust.id_for_noise_key(&remote_static);

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
    let noise_keys = noise_keys_for_identity(&config.identity)?;
    let remote = trust
        .noise_key(peer_id)
        .ok_or_else(|| RouterError::Auth(format!("unknown peer {peer_id}")))?;
    let stream = tokio::net::TcpStream::connect(peer_addr).await?;
    let (mut reader, mut writer) = stream.into_split();

    let mut builder = snow::Builder::new(NOISE_PATTERN.parse().unwrap());
    builder = builder
        .local_private_key(&noise_keys.private)
        .remote_public_key(remote);
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

async fn connect_noise_with_key(
    peer_addr: &str,
    peer_id: &str,
    peer_key: [u8; 32],
    config: &MeshConfig,
) -> Result<NoiseSession, RouterError> {
    let noise_keys = noise_keys_for_identity(&config.identity)?;
    let remote = ed25519_public_to_x25519(peer_key)?;
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

    let proxied = Request::from_parts(parts.0, parts.1);

    let response = match state.client.request(proxied).await {
        Ok(resp) => resp,
        Err(err) => {
            eprintln!("router request failed: {err}");
            return error_response(StatusCode::BAD_GATEWAY, "upstream request failed");
        }
    };

    let mut parts = response.into_parts();
    sanitize_response_headers(&mut parts.0.headers);
    let body = parts.1.boxed();
    Response::from_parts(parts.0, body)
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

    let mut target_url = base;
    target_url.set_path(req.uri().path());
    target_url.set_query(req.uri().query());

    Ok(target_url)
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
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(peer_key.as_bytes())
        .map_err(|err| RouterError::InvalidConfig(format!("invalid peer_key: {err}")))?;
    let peer_key: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| RouterError::InvalidConfig("invalid peer_key length".to_string()))?;

    Ok(MeshExternalTarget {
        peer_addr: format!("{host}:{port}"),
        peer_id,
        peer_key,
    })
}

fn error_response(status: StatusCode, message: &str) -> Response<BoxBody> {
    let body = Full::new(Bytes::from(message.to_string()))
        .map_err(|err| match err {})
        .boxed();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(body)
        .unwrap_or_else(|_| {
            Response::new(Full::new(Bytes::new()).map_err(|err| match err {}).boxed())
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
            noise_by_id,
            id_by_noise,
        })
    }

    fn noise_key(&self, id: &str) -> Option<&[u8; 32]> {
        self.noise_by_id.get(id)
    }

    fn id_for_noise_key(&self, key: &[u8; 32]) -> Option<String> {
        self.id_by_noise.get(key).cloned()
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
