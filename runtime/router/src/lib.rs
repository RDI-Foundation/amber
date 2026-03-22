use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    env,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{Arc, Mutex as StdMutex},
};

use amber_mesh::{
    HttpRoutePlugin, InboundRoute, InboundTarget, MeshConfig, MeshConfigPublic, MeshIdentity,
    MeshIdentityPublic, MeshIdentitySecret, MeshPeer, MeshProtocol, OutboundRoute,
    component_route_id,
    telemetry::{OtlpLogMessage, OtlpTraceContext, emit_otlp_log},
};
use base64::Engine as _;
use bytes::Bytes;
use curve25519_dalek::edwards::CompressedEdwardsY;
use futures::StreamExt as _;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri, header};
use http_body_util::{BodyExt as _, BodyStream, Full, StreamBody};
use hyper::{
    body::{Body as _, Frame, Incoming},
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
use opentelemetry::{
    Key,
    logs::{AnyValue, Severity},
    trace::TraceContextExt as _,
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
use tracing::Instrument as _;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    slot: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    capability_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    capability_profile: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HttpEdgeKind {
    Binding,
    ExternalSlot,
    Export,
}

impl HttpEdgeKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Binding => "binding",
            Self::ExternalSlot => "external_slot",
            Self::Export => "export",
        }
    }
}

#[derive(Clone)]
struct HttpExchangeLabels {
    kind: HttpEdgeKind,
    emit_telemetry: bool,
    slot: Option<Arc<str>>,
    capability: Arc<str>,
    capability_kind: Option<Arc<str>>,
    capability_profile: Option<Arc<str>>,
    source_component: Option<Arc<str>>,
    source_endpoint: Arc<str>,
    destination_component: Option<Arc<str>>,
    destination_endpoint: Arc<str>,
}

impl HttpExchangeLabels {
    fn inbound_from_route(
        local_id: Arc<str>,
        remote_id: Arc<str>,
        route: &InboundRoute,
        open: &OpenFrame,
    ) -> Self {
        let slot = open.slot.as_deref().map(Arc::<str>::from);
        let capability = Arc::<str>::from(route.capability.as_str());
        let capability_kind = route
            .capability_kind
            .clone()
            .or_else(|| open.capability_kind.clone())
            .map(Arc::<str>::from);
        let capability_profile = route
            .capability_profile
            .clone()
            .or_else(|| open.capability_profile.clone())
            .map(Arc::<str>::from);
        let source_from_open = source_endpoint_from_open(open);
        let router_forwarded_export = remote_id.as_ref() == "/router" && source_from_open.is_some();

        let (
            kind,
            emit_telemetry,
            source_component,
            source_endpoint,
            destination_component,
            destination_endpoint,
        ) = match &route.target {
            InboundTarget::Local { .. } => {
                if router_forwarded_export {
                    (
                        HttpEdgeKind::Export,
                        false,
                        None,
                        source_from_open
                            .clone()
                            .unwrap_or_else(|| capability.clone()),
                        Some(local_id.clone()),
                        capability.clone(),
                    )
                } else {
                    (
                        HttpEdgeKind::Binding,
                        true,
                        Some(remote_id.clone()),
                        source_from_open.unwrap_or_else(|| capability.clone()),
                        Some(local_id.clone()),
                        capability.clone(),
                    )
                }
            }
            InboundTarget::External { .. } => (
                HttpEdgeKind::ExternalSlot,
                true,
                Some(remote_id.clone()),
                source_from_open.unwrap_or_else(|| capability.clone()),
                None,
                capability.clone(),
            ),
            InboundTarget::MeshForward {
                peer_id,
                capability: forward_capability,
                ..
            } => (
                HttpEdgeKind::Export,
                true,
                None,
                source_from_open.unwrap_or_else(|| capability.clone()),
                Some(Arc::<str>::from(peer_id.as_str())),
                Arc::<str>::from(forward_capability.as_str()),
            ),
        };

        Self {
            kind,
            emit_telemetry,
            slot,
            capability,
            capability_kind,
            capability_profile,
            source_component,
            source_endpoint,
            destination_component,
            destination_endpoint,
        }
    }

    fn outbound_from_route(local_id: Arc<str>, route: &OutboundRoute) -> Self {
        let kind = if route.peer_id == "/router" {
            HttpEdgeKind::ExternalSlot
        } else {
            HttpEdgeKind::Binding
        };
        let destination_component = match kind {
            HttpEdgeKind::ExternalSlot => None,
            HttpEdgeKind::Binding | HttpEdgeKind::Export => {
                Some(Arc::<str>::from(route.peer_id.as_str()))
            }
        };
        Self {
            kind,
            emit_telemetry: true,
            slot: Some(Arc::<str>::from(route.slot.as_str())),
            capability: Arc::<str>::from(route.capability.as_str()),
            capability_kind: route.capability_kind.as_deref().map(Arc::<str>::from),
            capability_profile: route.capability_profile.as_deref().map(Arc::<str>::from),
            source_component: Some(local_id.clone()),
            source_endpoint: Arc::<str>::from(route.slot.as_str()),
            destination_component,
            destination_endpoint: Arc::<str>::from(route.capability.as_str()),
        }
    }
}

fn source_endpoint_from_open(open: &OpenFrame) -> Option<Arc<str>> {
    open.slot.as_deref().map(Arc::<str>::from).or_else(|| {
        (!open.capability.is_empty()).then(|| Arc::<str>::from(open.capability.as_str()))
    })
}

#[derive(Clone)]
struct HttpProxyState {
    client: HttpClient,
    target: ExternalTarget,
    labels: HttpExchangeLabels,
    config: Arc<MeshConfig>,
    external_overrides: ExternalOverrides,
    mesh_upstream: Arc<Mutex<Option<MeshHttpUpstream>>>,
}

#[derive(Clone)]
struct LocalHttpProxyState {
    client: HttpClient,
    base_url: Url,
    plugins: Arc<[Arc<dyn HttpExchangePlugin>]>,
    route_id: Arc<str>,
    labels: HttpExchangeLabels,
}

#[derive(Clone)]
struct OutboundHttpProxyState {
    upstream: Arc<Mutex<client_http1::SendRequest<BoxBody>>>,
    plugins: Arc<[Arc<dyn HttpExchangePlugin>]>,
    route_id: Arc<str>,
    labels: HttpExchangeLabels,
}

type HttpClient = Client<HttpsConnector<HttpConnector>, BoxBody>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BodyMode {
    Stream,
    Collect,
}

enum FilterDecision {
    Continue,
    #[allow(dead_code)]
    Reject {
        status: StatusCode,
        message: String,
    },
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HttpLifecyclePart {
    Request,
    Response,
}

impl RewriteFlow {
    fn as_str(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
    }

    fn otel_kind(self) -> &'static str {
        match self {
            Self::Inbound => "server",
            Self::Outbound => "client",
        }
    }

    fn local_role(self) -> &'static str {
        match self {
            Self::Inbound => "receiver",
            Self::Outbound => "sender",
        }
    }

    fn peer_role(self) -> &'static str {
        match self {
            Self::Inbound => "sender",
            Self::Outbound => "receiver",
        }
    }

    fn lifecycle_stage(self, part: HttpLifecyclePart) -> &'static str {
        match (self, part) {
            (Self::Outbound, HttpLifecyclePart::Request) => "sender_request",
            (Self::Inbound, HttpLifecyclePart::Request) => "receiver_request",
            (Self::Inbound, HttpLifecyclePart::Response) => "receiver_response",
            (Self::Outbound, HttpLifecyclePart::Response) => "sender_response",
        }
    }
}

#[derive(Clone)]
struct HttpExchangeTelemetryContext {
    flow: RewriteFlow,
    flow_name: &'static str,
    otel_kind: &'static str,
    local_role: &'static str,
    peer_role: &'static str,
    edge_kind: HttpEdgeKind,
    capability: Arc<str>,
    slot: Option<Arc<str>>,
    capability_kind: Option<Arc<str>>,
    capability_profile: Option<Arc<str>>,
    source_component: Option<Arc<str>>,
    source_endpoint: Arc<str>,
    destination_component: Option<Arc<str>>,
    destination_endpoint: Arc<str>,
    source_ref: Arc<str>,
    destination_ref: Arc<str>,
    edge_ref: Arc<str>,
    summary: Arc<StdMutex<ProtocolSummary>>,
}

impl HttpExchangeTelemetryContext {
    fn new(flow: RewriteFlow, labels: &HttpExchangeLabels) -> Self {
        let source_ref = Arc::<str>::from(source_ref_for(labels).into_boxed_str());
        let destination_ref = Arc::<str>::from(destination_ref_for(labels).into_boxed_str());
        let edge_ref = Arc::<str>::from(
            edge_ref_for(flow, labels, &source_ref, &destination_ref).into_boxed_str(),
        );
        Self {
            flow,
            flow_name: flow.as_str(),
            otel_kind: flow.otel_kind(),
            local_role: flow.local_role(),
            peer_role: flow.peer_role(),
            edge_kind: labels.kind,
            capability: labels.capability.clone(),
            slot: labels.slot.clone(),
            capability_kind: labels.capability_kind.clone(),
            capability_profile: labels.capability_profile.clone(),
            source_component: labels.source_component.clone(),
            source_endpoint: labels.source_endpoint.clone(),
            destination_component: labels.destination_component.clone(),
            destination_endpoint: labels.destination_endpoint.clone(),
            source_ref,
            destination_ref,
            edge_ref,
            summary: Arc::new(StdMutex::new(ProtocolSummary::default())),
        }
    }

    fn slot(&self) -> &str {
        self.slot.as_deref().unwrap_or("")
    }

    fn capability_kind(&self) -> &str {
        self.capability_kind.as_deref().unwrap_or("")
    }

    fn capability_profile(&self) -> &str {
        self.capability_profile.as_deref().unwrap_or("")
    }

    fn local_role(&self) -> &'static str {
        self.local_role
    }

    fn peer_role(&self) -> &'static str {
        self.peer_role
    }

    fn lifecycle_stage(&self, part: HttpLifecyclePart) -> &'static str {
        self.flow.lifecycle_stage(part)
    }

    fn edge_kind(&self) -> &'static str {
        self.edge_kind.as_str()
    }

    fn source_component(&self) -> &str {
        self.source_component.as_deref().unwrap_or("")
    }

    fn source_endpoint(&self) -> &str {
        self.source_endpoint.as_ref()
    }

    fn destination_component(&self) -> &str {
        self.destination_component
            .as_deref()
            .filter(|component| !component.is_empty())
            .unwrap_or(match self.edge_kind {
                HttpEdgeKind::ExternalSlot => "external",
                HttpEdgeKind::Binding | HttpEdgeKind::Export => "",
            })
    }

    fn destination_endpoint(&self) -> &str {
        self.destination_endpoint.as_ref()
    }

    fn source_ref(&self) -> &str {
        self.source_ref.as_ref()
    }

    fn destination_ref(&self) -> &str {
        self.destination_ref.as_ref()
    }

    fn edge_ref(&self) -> &str {
        self.edge_ref.as_ref()
    }

    fn span_name(&self, req: &Request<Incoming>) -> String {
        format!("{} {} {}", self.edge_ref(), req.method(), req.uri().path())
    }

    fn remember_summary(&self, summary: &ProtocolSummary) {
        if summary.is_empty() {
            return;
        }
        let mut state = self.summary.lock().unwrap_or_else(|err| err.into_inner());
        state.merge_from(summary);
    }

    fn summary_snapshot(&self) -> ProtocolSummary {
        self.summary
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .clone()
    }
}

fn component_endpoint_ref(
    component: Option<&str>,
    endpoint: &str,
    root_prefix: Option<&str>,
) -> String {
    match component {
        Some(component) if !component.is_empty() => format!("{component}.{endpoint}"),
        _ => match root_prefix {
            Some(prefix) => format!("{prefix}.{endpoint}"),
            None => endpoint.to_string(),
        },
    }
}

fn source_ref_for(labels: &HttpExchangeLabels) -> String {
    match labels.kind {
        HttpEdgeKind::Export => labels.source_endpoint.to_string(),
        HttpEdgeKind::Binding => component_endpoint_ref(
            labels.source_component.as_deref(),
            labels.source_endpoint.as_ref(),
            None,
        ),
        HttpEdgeKind::ExternalSlot => component_endpoint_ref(
            labels.source_component.as_deref(),
            labels.source_endpoint.as_ref(),
            None,
        ),
    }
}

fn destination_ref_for(labels: &HttpExchangeLabels) -> String {
    match labels.kind {
        HttpEdgeKind::ExternalSlot => component_endpoint_ref(
            labels.destination_component.as_deref(),
            labels.destination_endpoint.as_ref(),
            Some("external"),
        ),
        HttpEdgeKind::Binding | HttpEdgeKind::Export => component_endpoint_ref(
            labels.destination_component.as_deref(),
            labels.destination_endpoint.as_ref(),
            None,
        ),
    }
}

fn edge_ref_for(
    flow: RewriteFlow,
    labels: &HttpExchangeLabels,
    source_ref: &str,
    destination_ref: &str,
) -> String {
    match labels.kind {
        HttpEdgeKind::Export => labels.source_endpoint.to_string(),
        HttpEdgeKind::Binding | HttpEdgeKind::ExternalSlot => {
            let _ = flow;
            format!("{source_ref} -> {destination_ref}")
        }
    }
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

#[derive(Debug)]
struct MeshHttpUpstream {
    target_url: String,
    sender: client_http1::SendRequest<BoxBody>,
    conn_task: tokio::task::JoinHandle<()>,
    bridge_task: tokio::task::JoinHandle<Result<(), RouterError>>,
}

impl MeshHttpUpstream {
    fn is_reusable_for(&self, target_url: &str) -> bool {
        self.target_url == target_url
            && !self.conn_task.is_finished()
            && !self.bridge_task.is_finished()
    }
}

impl Drop for MeshHttpUpstream {
    fn drop(&mut self) {
        self.conn_task.abort();
        self.bridge_task.abort();
    }
}

#[derive(Clone, Debug)]
enum ResolvedHttpExternalTarget {
    Http(Url),
    Mesh {
        target_url: String,
        mesh: MeshExternalTarget,
    },
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

async fn shutdown_signal() {
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
                tracing::warn!(target: "amber.internal", "mesh tcp connection failed: {err}");
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
                proxy_noise_to_local_http(
                    &mut session,
                    route.route_id.clone().into(),
                    port,
                    client.clone(),
                    plugins,
                    HttpExchangeLabels::inbound_from_route(
                        config.identity.id.clone().into(),
                        remote_id.clone().into(),
                        &route,
                        &open,
                    ),
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
                proxy_noise_to_external(
                    &mut session,
                    HttpExchangeLabels::inbound_from_route(
                        config.identity.id.clone().into(),
                        remote_id.clone().into(),
                        &route,
                        &open,
                    ),
                    ExternalTarget {
                        name: route.capability.clone(),
                        url_env: url_env.clone(),
                        optional,
                        url_override: None,
                    },
                    client.clone(),
                    config.clone(),
                    external_overrides.clone(),
                )
                .await?;
            }
            MeshProtocol::Tcp => {
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
        slot: None,
        capability_kind: None,
        capability_profile: None,
    };
    outbound.send_open(&open).await?;
    proxy_noise_to_noise(session, outbound).await?;
    Ok(true)
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
                tracing::warn!(target: "amber.internal", "outbound connection failed: {err}");
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
            stream,
            plugins,
            HttpExchangeLabels::outbound_from_route(config.identity.id.clone().into(), &route),
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
                tracing::warn!(target: "amber.internal", "control connection failed: {err}");
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
    let listener = bind_unix_listener(path.as_str())?;
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
                tracing::warn!(target: "amber.internal", "control unix connection failed: {err}");
            }
        });
    }
}

#[cfg(unix)]
fn bind_unix_listener(path: &str) -> Result<UnixListener, RouterError> {
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
    labels: HttpExchangeLabels,
    target: ExternalTarget,
    client: Arc<HttpClient>,
    config: Arc<MeshConfig>,
    external_overrides: ExternalOverrides,
) -> Result<(), RouterError> {
    let (local, remote) = duplex(64 * 1024);
    let mut noise_session = session.clone();

    let bridge = tokio::spawn(async move { proxy_noise_to_plain(&mut noise_session, local).await });

    let state = HttpProxyState {
        client: (*client).clone(),
        target,
        labels,
        config,
        external_overrides,
        mesh_upstream: Arc::new(Mutex::new(None)),
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
    validate_external_host(host.as_str(), port)
        .await
        .map_err(RouterError::InvalidConfig)?;
    let upstream = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
    proxy_noise_to_plain(session, upstream).await
}

async fn proxy_noise_to_local_http(
    session: &mut NoiseSession,
    route_id: Arc<str>,
    port: u16,
    client: Arc<HttpClient>,
    plugins: Arc<[Arc<dyn HttpExchangePlugin>]>,
    labels: HttpExchangeLabels,
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
        labels,
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

async fn proxy_noise_to_noise_http(
    session: &mut NoiseSession,
    outbound: NoiseSession,
    route_id: Arc<str>,
    plugins: Arc<[Arc<dyn HttpExchangePlugin>]>,
    labels: HttpExchangeLabels,
) -> Result<(), RouterError> {
    let (incoming_local, incoming_remote) = duplex(64 * 1024);
    let mut incoming_session = session.clone();
    let incoming_bridge =
        tokio::spawn(
            async move { proxy_noise_to_plain(&mut incoming_session, incoming_local).await },
        );

    let (outgoing_local, outgoing_remote) = duplex(64 * 1024);
    let mut outgoing_session = outbound.clone();
    let outgoing_bridge =
        tokio::spawn(
            async move { proxy_noise_to_plain(&mut outgoing_session, outgoing_remote).await },
        );

    let (sender, conn) = client_http1::handshake(TokioIo::new(outgoing_local))
        .await
        .map_err(|err| {
            RouterError::Transport(format!("outbound upstream handshake failed: {err}"))
        })?;
    let conn_task = tokio::spawn(async move {
        if let Err(err) = conn.await {
            tracing::warn!(target: "amber.internal", "outbound upstream connection failed: {err}");
        }
    });

    let state = OutboundHttpProxyState {
        upstream: Arc::new(Mutex::new(sender)),
        plugins,
        route_id,
        labels,
    };

    let service = ServiceBuilder::new()
        .layer(CompressionLayer::new())
        .service(tower_service_fn(move |req| {
            let state = state.clone();
            async move {
                Ok::<_, std::convert::Infallible>(
                    proxy_inbound_http_request_to_noise(state, req).await,
                )
            }
        }));
    let service = TowerToHyperService::new(service);

    if let Err(err) = hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(incoming_remote), service)
        .await
    {
        return Err(RouterError::Transport(err.to_string()));
    }

    let _ = conn_task.await;
    let _ = outgoing_bridge.await;
    let _ = incoming_bridge.await;
    Ok(())
}

const DEFAULT_HTTP_BODY_CAPTURE_LIMIT_BYTES: usize = 256 * 1024;

// We keep local HeaderMap adapters because opentelemetry-http currently uses
// `http` 0.2 while the router stack uses `http` 1.x.
struct HeaderMapExtractor<'a>(&'a HeaderMap);

impl opentelemetry::propagation::Extractor for HeaderMapExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| value.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|name| name.as_str()).collect()
    }
}

struct HeaderMapInjector<'a>(&'a mut HeaderMap);

impl opentelemetry::propagation::Injector for HeaderMapInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let Ok(name) = http::header::HeaderName::from_bytes(key.as_bytes())
            && let Ok(value) = HeaderValue::from_str(&value)
        {
            self.0.insert(name, value);
        }
    }
}

fn start_http_exchange_span(
    telemetry: &HttpExchangeTelemetryContext,
    req: &Request<Incoming>,
) -> tracing::Span {
    let parent_context = opentelemetry::global::get_text_map_propagator(|prop| {
        prop.extract(&HeaderMapExtractor(req.headers()))
    });
    let span_name = telemetry.span_name(req);

    let span = tracing::info_span!(
        "amber.binding",
        otel.name = span_name.as_str(),
        otel.kind = telemetry.otel_kind,
        otel.status_code = tracing::field::Empty,
        otel.status_description = tracing::field::Empty,
        amber_entity_kind = "binding",
        amber_edge_kind = telemetry.edge_kind(),
        amber_edge_ref = telemetry.edge_ref(),
        amber_source_ref = telemetry.source_ref(),
        amber_source_component = telemetry.source_component(),
        amber_source_endpoint = telemetry.source_endpoint(),
        amber_destination_ref = telemetry.destination_ref(),
        amber_destination_component = telemetry.destination_component(),
        amber_destination_endpoint = telemetry.destination_endpoint(),
        amber_flow = telemetry.flow_name,
        amber_local_role = telemetry.local_role(),
        amber_peer_role = telemetry.peer_role(),
        amber_transport = "http",
        amber_exchange_id = tracing::field::Empty,
        amber_trace_id = tracing::field::Empty,
        amber_application_error = tracing::field::Empty,
        amber_protocol = tracing::field::Empty,
        amber_rpc_kind = tracing::field::Empty,
        amber_rpc_method = tracing::field::Empty,
        amber_request_key = tracing::field::Empty,
        amber_rpc_id = tracing::field::Empty,
        amber_capability = telemetry.capability.as_ref(),
        amber_slot = telemetry.slot(),
        amber_capability_kind = telemetry.capability_kind(),
        amber_capability_profile = telemetry.capability_profile(),
        "http.request.method" = %req.method(),
        "url.path" = %req.uri().path(),
        "http.response.status_code" = tracing::field::Empty,
        http_method = %req.method(),
        http_path = %req.uri().path(),
        http_status_code = tracing::field::Empty,
    );
    let _ = span.set_parent(parent_context);
    record_exchange_identity(&span);
    span
}

fn inject_trace_context(span: &tracing::Span, headers: &mut HeaderMap) {
    let context = span.context();
    opentelemetry::global::get_text_map_propagator(|prop| {
        prop.inject_context(&context, &mut HeaderMapInjector(headers))
    });
}

fn current_exchange_ids(span: &tracing::Span) -> (String, String) {
    let span_context = span.context().span().span_context().clone();
    if span_context.is_valid() {
        (
            span_context.trace_id().to_string(),
            span_context.span_id().to_string(),
        )
    } else {
        (String::new(), String::new())
    }
}

fn record_exchange_identity(span: &tracing::Span) {
    let (trace_id, exchange_id) = current_exchange_ids(span);
    if !trace_id.is_empty() {
        span.record("amber_trace_id", trace_id.as_str());
    }
    if !exchange_id.is_empty() {
        span.record("amber_exchange_id", exchange_id.as_str());
    }
}

fn record_http_status(span: &tracing::Span, status: StatusCode, application_error: bool) {
    let status_code = status.as_u16();
    span.record("http_status_code", status_code);
    span.record("http.response.status_code", status_code);
    span.record(
        "otel.status_code",
        if application_error || status.as_u16() >= 500 {
            "error"
        } else {
            otel_status_code_for_http(status)
        },
    );
}

fn finalize_http_exchange_response(
    span: &tracing::Span,
    telemetry: &HttpExchangeTelemetryContext,
    response: Response<BoxBody>,
) -> Response<BoxBody> {
    let status = response.status();
    let summary = telemetry.summary_snapshot();
    record_http_status(span, status, summary.has_application_error());
    if let Some(message) = summary.application_error_message() {
        span.record("otel.status_description", message.as_str());
    } else if status.is_server_error() {
        span.record(
            "otel.status_description",
            status.canonical_reason().unwrap_or("server error"),
        );
    }
    response
}

fn otel_status_code_for_http(status: StatusCode) -> &'static str {
    if status.as_u16() >= 500 {
        "error"
    } else {
        "ok"
    }
}

fn headers_to_json(headers: &HeaderMap) -> String {
    let mut values: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, value) in headers {
        values
            .entry(name.as_str().to_string())
            .or_default()
            .push(String::from_utf8_lossy(value.as_bytes()).into_owned());
    }
    serde_json::to_string(&values).unwrap_or_else(|_| "{}".to_string())
}

#[derive(Clone, Debug, Default, PartialEq)]
struct ProtocolSummary {
    protocol: Option<&'static str>,
    rpc_kind: Option<&'static str>,
    rpc_method_raw: Option<String>,
    rpc_method: Option<String>,
    rpc_id: Option<String>,
    rpc_is_notification: Option<bool>,
    rpc_error_code: Option<i64>,
    rpc_error_message: Option<String>,
    request_key: Option<String>,
    parent_request_key: Option<String>,
    mcp_tool_name: Option<String>,
    mcp_task_id: Option<String>,
    mcp_progress_token: Option<String>,
    mcp_progress: Option<f64>,
    mcp_progress_total: Option<f64>,
    mcp_progress_message: Option<String>,
    mcp_resource_uri: Option<String>,
    mcp_cursor: Option<String>,
    mcp_next_cursor: Option<String>,
    mcp_list_changed: Option<bool>,
    mcp_tool_is_error: Option<bool>,
    mcp_log_level: Option<String>,
    mcp_logger: Option<String>,
    a2a_message_id: Option<String>,
    a2a_task_id: Option<String>,
    a2a_context_id: Option<String>,
    a2a_reference_task_id: Option<String>,
    a2a_task_state: Option<String>,
    a2a_artifact_count: Option<i64>,
}

impl ProtocolSummary {
    fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    fn merge_from(&mut self, other: &Self) {
        macro_rules! merge_field {
            ($field:ident) => {
                if other.$field.is_some() {
                    self.$field = other.$field.clone();
                }
            };
        }

        merge_field!(protocol);
        merge_field!(rpc_kind);
        merge_field!(rpc_method_raw);
        merge_field!(rpc_method);
        merge_field!(rpc_id);
        merge_field!(rpc_is_notification);
        merge_field!(rpc_error_code);
        merge_field!(rpc_error_message);
        merge_field!(request_key);
        merge_field!(parent_request_key);
        merge_field!(mcp_tool_name);
        merge_field!(mcp_task_id);
        merge_field!(mcp_progress_token);
        merge_field!(mcp_progress);
        merge_field!(mcp_progress_total);
        merge_field!(mcp_progress_message);
        merge_field!(mcp_resource_uri);
        merge_field!(mcp_cursor);
        merge_field!(mcp_next_cursor);
        merge_field!(mcp_list_changed);
        merge_field!(mcp_tool_is_error);
        merge_field!(mcp_log_level);
        merge_field!(mcp_logger);
        merge_field!(a2a_message_id);
        merge_field!(a2a_task_id);
        merge_field!(a2a_context_id);
        merge_field!(a2a_reference_task_id);
        merge_field!(a2a_task_state);
        merge_field!(a2a_artifact_count);
    }

    fn has_application_error(&self) -> bool {
        self.rpc_error_code.is_some()
            || self.mcp_tool_is_error == Some(true)
            || self
                .a2a_task_state
                .as_deref()
                .is_some_and(|state| state.eq_ignore_ascii_case("TASK_STATE_FAILED"))
    }

    fn application_error_message(&self) -> Option<String> {
        self.rpc_error_message
            .clone()
            .or_else(|| {
                self.rpc_error_code
                    .map(|code| format!("json-rpc error {code}"))
            })
            .or_else(|| {
                (self.mcp_tool_is_error == Some(true))
                    .then_some("tool call returned isError=true".to_string())
            })
            .or_else(|| {
                self.a2a_task_state.as_ref().and_then(|state| {
                    state
                        .eq_ignore_ascii_case("TASK_STATE_FAILED")
                        .then_some(format!("a2a task ended in {state}"))
                })
            })
    }
}

fn exchange_message(
    telemetry: &HttpExchangeTelemetryContext,
    part: HttpLifecyclePart,
    summary: &ProtocolSummary,
) -> String {
    let source_component = telemetry.source_component();
    let destination_component = telemetry.destination_component();
    let edge_ref = telemetry.edge_ref();
    let base = match telemetry.edge_kind {
        HttpEdgeKind::Export => match part {
            HttpLifecyclePart::Request => format!(
                "request received from {} by {}",
                telemetry.source_ref(),
                if destination_component.is_empty() {
                    telemetry.destination_ref()
                } else {
                    destination_component
                }
            ),
            HttpLifecyclePart::Response => format!(
                "response sent from {} to {}",
                if destination_component.is_empty() {
                    telemetry.destination_ref()
                } else {
                    destination_component
                },
                telemetry.source_ref(),
            ),
        },
        HttpEdgeKind::ExternalSlot => match part {
            HttpLifecyclePart::Request => format!(
                "request sent from {} to external slot {} via {}",
                if source_component.is_empty() {
                    telemetry.source_ref()
                } else {
                    source_component
                },
                telemetry.destination_endpoint(),
                edge_ref,
            ),
            HttpLifecyclePart::Response => format!(
                "response received by {} from external slot {} via {}",
                if source_component.is_empty() {
                    telemetry.source_ref()
                } else {
                    source_component
                },
                telemetry.destination_endpoint(),
                edge_ref,
            ),
        },
        HttpEdgeKind::Binding => match (telemetry.flow, part) {
            (RewriteFlow::Outbound, HttpLifecyclePart::Request) => format!(
                "request sent from {} to {} via {}",
                if source_component.is_empty() {
                    telemetry.source_ref()
                } else {
                    source_component
                },
                if destination_component.is_empty() {
                    telemetry.destination_ref()
                } else {
                    destination_component
                },
                edge_ref,
            ),
            (RewriteFlow::Inbound, HttpLifecyclePart::Request) => format!(
                "request received by {} from {} via {}",
                if destination_component.is_empty() {
                    telemetry.destination_ref()
                } else {
                    destination_component
                },
                if source_component.is_empty() {
                    telemetry.source_ref()
                } else {
                    source_component
                },
                edge_ref,
            ),
            (RewriteFlow::Inbound, HttpLifecyclePart::Response) => format!(
                "response sent from {} to {} via {}",
                if destination_component.is_empty() {
                    telemetry.destination_ref()
                } else {
                    destination_component
                },
                if source_component.is_empty() {
                    telemetry.source_ref()
                } else {
                    source_component
                },
                edge_ref,
            ),
            (RewriteFlow::Outbound, HttpLifecyclePart::Response) => format!(
                "response received by {} from {} via {}",
                if source_component.is_empty() {
                    telemetry.source_ref()
                } else {
                    source_component
                },
                if destination_component.is_empty() {
                    telemetry.destination_ref()
                } else {
                    destination_component
                },
                edge_ref,
            ),
        },
    };
    match protocol_detail(summary, part) {
        Some(detail) => format!("{base}: {detail}"),
        None => base,
    }
}

fn emit_binding_failure_event(
    span: &tracing::Span,
    telemetry: &HttpExchangeTelemetryContext,
    status: StatusCode,
    reason: &str,
    error_detail: Option<String>,
) {
    let summary = telemetry.summary_snapshot();
    let mut message = exchange_message(telemetry, HttpLifecyclePart::Request, &summary);
    message.push_str(" failed");
    if !reason.is_empty() {
        message.push_str(": ");
        message.push_str(reason);
    }

    let mut extra_attributes = Vec::with_capacity(2);
    push_log_attr(
        &mut extra_attributes,
        "http.response.status_code",
        i64::from(status.as_u16()),
    );
    if let Some(error_detail) = error_detail {
        push_nonempty_log_attr(
            &mut extra_attributes,
            "error.message",
            error_detail.as_str(),
        );
    }
    emit_binding_log(
        span,
        telemetry,
        &summary,
        BindingLogSpec {
            level: Severity::Warn,
            part: HttpLifecyclePart::Response,
            step: "error",
            transport: "http",
            event_name: "amber.binding.error",
            message,
            extra_attributes,
        },
    );
}

fn protocol_detail(summary: &ProtocolSummary, part: HttpLifecyclePart) -> Option<String> {
    let mut action = summary
        .rpc_method
        .as_deref()
        .or(summary.rpc_method_raw.as_deref())
        .map(ToString::to_string)
        .or_else(|| {
            summary
                .mcp_tool_name
                .as_ref()
                .map(|tool_name| format!("tool {tool_name}"))
        })
        .or_else(|| {
            summary
                .a2a_task_state
                .as_ref()
                .map(|task_state| format!("A2A {task_state}"))
        })
        .or_else(|| summary.mcp_progress.map(|_| "MCP progress".to_string()));

    if action.as_deref() == Some("tools/call")
        && let Some(tool_name) = summary.mcp_tool_name.as_deref()
    {
        action = Some(format!("tools/call {tool_name}"));
    }

    let mut detail = match (part, action) {
        (HttpLifecyclePart::Request, Some(action)) => {
            if summary.rpc_is_notification == Some(true) {
                format!("{action} notification")
            } else {
                action
            }
        }
        (HttpLifecyclePart::Response, Some(action)) => {
            if let Some(code) = summary.rpc_error_code {
                format!("{action} error {code}")
            } else if summary.has_application_error() {
                format!("{action} error")
            } else if summary.rpc_kind == Some("result") {
                format!("{action} result")
            } else {
                format!("{action} response")
            }
        }
        (_, None) => return None,
    };

    if let Some(id) = summary.rpc_id.as_deref().filter(|id| !id.is_empty()) {
        detail.push_str(&format!(" (id={id})"));
    }

    Some(detail)
}

#[derive(Clone, Debug, Default)]
struct JsonRpcExtraction {
    kind: Option<&'static str>,
    method_raw: Option<String>,
    method: Option<String>,
    id: Option<String>,
    is_notification: Option<bool>,
    error_code: Option<i64>,
    error_message: Option<String>,
}

#[derive(Clone, Copy)]
struct EventProtocolFields<'a> {
    protocol: &'a str,
    rpc_kind: &'a str,
    request_key: &'a str,
    rpc_id: &'a str,
    rpc_method: &'a str,
    application_error: bool,
}

fn protocol_fields(summary: &ProtocolSummary) -> EventProtocolFields<'_> {
    EventProtocolFields {
        protocol: summary.protocol.unwrap_or(""),
        rpc_kind: summary.rpc_kind.unwrap_or(""),
        request_key: summary.request_key.as_deref().unwrap_or(""),
        rpc_id: summary.rpc_id.as_deref().unwrap_or(""),
        rpc_method: summary.rpc_method.as_deref().unwrap_or(""),
        application_error: summary.has_application_error(),
    }
}

fn record_protocol_summary(span: &tracing::Span, summary: &ProtocolSummary) {
    if let Some(protocol) = summary.protocol {
        span.record("amber_protocol", protocol);
    }
    if let Some(kind) = summary.rpc_kind {
        span.record("amber_rpc_kind", kind);
    }
    if let Some(method) = summary.rpc_method.as_deref() {
        span.record("amber_rpc_method", method);
    }
    if let Some(request_key) = summary.request_key.as_deref() {
        span.record("amber_request_key", request_key);
    }
    if let Some(rpc_id) = summary.rpc_id.as_deref() {
        span.record("amber_rpc_id", rpc_id);
    }
    if summary.has_application_error() {
        span.record("amber_application_error", true);
        span.record("otel.status_code", "error");
        if let Some(message) = summary.application_error_message() {
            span.record("otel.status_description", message.as_str());
        }
    }
}

type OtlpLogAttributes = Vec<(Key, AnyValue)>;

struct BindingLogSpec {
    level: Severity,
    part: HttpLifecyclePart,
    step: &'static str,
    transport: &'static str,
    event_name: &'static str,
    message: String,
    extra_attributes: OtlpLogAttributes,
}

fn push_log_attr<V>(attributes: &mut OtlpLogAttributes, key: &'static str, value: V)
where
    V: Into<AnyValue>,
{
    attributes.push((Key::new(key), value.into()));
}

fn push_nonempty_log_attr(attributes: &mut OtlpLogAttributes, key: &'static str, value: &str) {
    if !value.is_empty() {
        push_log_attr(attributes, key, value.to_string());
    }
}

fn push_true_log_attr(attributes: &mut OtlpLogAttributes, key: &'static str, value: bool) {
    if value {
        push_log_attr(attributes, key, value);
    }
}

fn binding_log_trace_context(span: &tracing::Span) -> Option<OtlpTraceContext> {
    let span_context = span.context().span().span_context().clone();
    span_context.is_valid().then_some(OtlpTraceContext {
        trace_id: span_context.trace_id(),
        span_id: span_context.span_id(),
        trace_flags: Some(span_context.trace_flags()),
    })
}

fn binding_log_attributes(
    telemetry: &HttpExchangeTelemetryContext,
    summary: &ProtocolSummary,
    trace_id: &str,
    exchange_id: &str,
    spec: &mut BindingLogSpec,
) -> OtlpLogAttributes {
    let fields = protocol_fields(summary);
    let mut attributes = Vec::with_capacity(24 + spec.extra_attributes.len());

    push_log_attr(&mut attributes, "amber_entity_kind", "binding");
    push_log_attr(&mut attributes, "amber_edge_kind", telemetry.edge_kind());
    push_nonempty_log_attr(&mut attributes, "amber_edge_ref", telemetry.edge_ref());
    push_nonempty_log_attr(&mut attributes, "amber_source_ref", telemetry.source_ref());
    push_nonempty_log_attr(
        &mut attributes,
        "amber_source_component",
        telemetry.source_component(),
    );
    push_nonempty_log_attr(
        &mut attributes,
        "amber_source_endpoint",
        telemetry.source_endpoint(),
    );
    push_nonempty_log_attr(
        &mut attributes,
        "amber_destination_ref",
        telemetry.destination_ref(),
    );
    push_nonempty_log_attr(
        &mut attributes,
        "amber_destination_component",
        telemetry.destination_component(),
    );
    push_nonempty_log_attr(
        &mut attributes,
        "amber_destination_endpoint",
        telemetry.destination_endpoint(),
    );
    push_log_attr(&mut attributes, "amber_flow", telemetry.flow_name);
    push_log_attr(&mut attributes, "amber_local_role", telemetry.local_role());
    push_log_attr(&mut attributes, "amber_peer_role", telemetry.peer_role());
    push_log_attr(
        &mut attributes,
        "amber_lifecycle_stage",
        telemetry.lifecycle_stage(spec.part),
    );
    push_log_attr(&mut attributes, "amber_exchange_step", spec.step);
    push_log_attr(&mut attributes, "amber_transport", spec.transport);
    push_nonempty_log_attr(&mut attributes, "amber_trace_id", trace_id);
    push_nonempty_log_attr(&mut attributes, "amber_exchange_id", exchange_id);
    push_nonempty_log_attr(
        &mut attributes,
        "amber_capability",
        telemetry.capability.as_ref(),
    );
    push_nonempty_log_attr(&mut attributes, "amber_slot", telemetry.slot());
    push_nonempty_log_attr(
        &mut attributes,
        "amber_capability_kind",
        telemetry.capability_kind(),
    );
    push_nonempty_log_attr(
        &mut attributes,
        "amber_capability_profile",
        telemetry.capability_profile(),
    );
    push_nonempty_log_attr(&mut attributes, "amber_protocol", fields.protocol);
    push_nonempty_log_attr(&mut attributes, "amber_rpc_kind", fields.rpc_kind);
    push_nonempty_log_attr(&mut attributes, "amber_request_key", fields.request_key);
    push_nonempty_log_attr(&mut attributes, "amber_rpc_id", fields.rpc_id);
    push_nonempty_log_attr(&mut attributes, "amber_rpc_method", fields.rpc_method);
    push_true_log_attr(
        &mut attributes,
        "amber_application_error",
        fields.application_error,
    );
    push_log_attr(&mut attributes, "event", spec.event_name);
    attributes.append(&mut spec.extra_attributes);
    attributes
}

fn emit_binding_console_log(level: Severity, span: &tracing::Span, message: &str) {
    span.in_scope(|| match level {
        Severity::Warn
        | Severity::Warn2
        | Severity::Warn3
        | Severity::Warn4
        | Severity::Error
        | Severity::Error2
        | Severity::Error3
        | Severity::Error4
        | Severity::Fatal
        | Severity::Fatal2
        | Severity::Fatal3
        | Severity::Fatal4 => tracing::warn!(target: "amber.binding", "{message}"),
        _ => tracing::info!(target: "amber.binding", "{message}"),
    });
}

fn emit_binding_log(
    span: &tracing::Span,
    telemetry: &HttpExchangeTelemetryContext,
    summary: &ProtocolSummary,
    mut spec: BindingLogSpec,
) {
    telemetry.remember_summary(summary);
    record_protocol_summary(span, summary);
    let (trace_id, exchange_id) = current_exchange_ids(span);

    emit_binding_console_log(spec.level, span, &spec.message);
    emit_otlp_log(OtlpLogMessage {
        scope_name: "amber.binding",
        target: "amber.binding",
        event_name: spec.event_name,
        severity: spec.level,
        body: spec.message.clone(),
        attributes: binding_log_attributes(
            telemetry,
            summary,
            trace_id.as_str(),
            exchange_id.as_str(),
            &mut spec,
        ),
        trace_context: binding_log_trace_context(span),
    });
}

fn emit_headers_event(
    span: &tracing::Span,
    telemetry: &HttpExchangeTelemetryContext,
    part: HttpLifecyclePart,
    event_name: &'static str,
    content_type: Option<&str>,
    content_encoding: Option<&str>,
    headers: &HeaderMap,
) {
    let headers_json = headers_to_json(headers);
    let summary = telemetry.summary_snapshot();
    let message = format!("{} [headers]", exchange_message(telemetry, part, &summary));
    let mut extra_attributes = Vec::with_capacity(3);
    push_nonempty_log_attr(
        &mut extra_attributes,
        "amber_headers_json",
        headers_json.as_str(),
    );
    push_nonempty_log_attr(
        &mut extra_attributes,
        "amber_body_content_type",
        content_type.unwrap_or(""),
    );
    push_nonempty_log_attr(
        &mut extra_attributes,
        "amber_body_content_encoding",
        content_encoding.unwrap_or(""),
    );
    emit_binding_log(
        span,
        telemetry,
        &summary,
        BindingLogSpec {
            level: Severity::Info,
            part,
            step: "headers",
            transport: "http",
            event_name,
            message,
            extra_attributes,
        },
    );
}

#[cfg(test)]
fn extract_json_rpc_from_text(body_text: &str) -> JsonRpcExtraction {
    if body_text.trim().is_empty() {
        return JsonRpcExtraction::default();
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body_text) else {
        return JsonRpcExtraction::default();
    };
    extract_json_rpc_from_value(&value)
}

fn extract_json_rpc_from_value(value: &serde_json::Value) -> JsonRpcExtraction {
    match value {
        serde_json::Value::Object(_) => extract_json_rpc_from_object(value),
        serde_json::Value::Array(values) => values
            .iter()
            .find_map(|item| {
                let extracted = extract_json_rpc_from_object(item);
                (extracted.method.is_some()
                    || extracted.id.is_some()
                    || extracted.error_code.is_some()
                    || extracted.kind.is_some())
                .then_some(extracted)
            })
            .unwrap_or_default(),
        _ => JsonRpcExtraction::default(),
    }
}

fn extract_json_rpc_from_object(value: &serde_json::Value) -> JsonRpcExtraction {
    let Some(obj) = value.as_object() else {
        return JsonRpcExtraction::default();
    };
    if obj.get("jsonrpc").and_then(|jsonrpc| jsonrpc.as_str()) != Some("2.0") {
        return JsonRpcExtraction::default();
    }

    let method_raw = obj
        .get("method")
        .and_then(|value| value.as_str())
        .map(ToString::to_string);
    let method = method_raw.as_deref().map(normalize_json_rpc_method);
    let id = obj.get("id").and_then(json_rpc_id_to_string);
    let error = obj.get("error").and_then(|value| value.as_object());
    let error_code = error
        .and_then(|error| error.get("code"))
        .and_then(|code| code.as_i64());
    let error_message = error
        .and_then(|error| error.get("message"))
        .and_then(|message| message.as_str())
        .map(ToString::to_string);
    let kind = if error.is_some() {
        Some("error")
    } else if obj.get("result").is_some() {
        Some("result")
    } else if method_raw.is_some() {
        Some(if id.is_some() {
            "request"
        } else {
            "notification"
        })
    } else {
        None
    };

    JsonRpcExtraction {
        kind,
        method_raw,
        method,
        id,
        is_notification: kind.map(|value| value == "notification"),
        error_code,
        error_message,
    }
}

fn normalize_json_rpc_method(method: &str) -> String {
    match method {
        "message/send" => "SendMessage".to_string(),
        "message/stream" => "SendStreamingMessage".to_string(),
        _ => method.to_string(),
    }
}

fn json_rpc_id_to_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::Null => Some("null".to_string()),
        _ => None,
    }
}

fn protocol_hint_for_exchange(
    telemetry: &HttpExchangeTelemetryContext,
    rpc: &JsonRpcExtraction,
) -> Option<&'static str> {
    match telemetry.capability_kind() {
        "mcp" => return Some("mcp"),
        "a2a" => return Some("a2a"),
        _ => {}
    }

    if rpc.method.as_deref().is_some_and(|method| {
        is_mcp_method(method) || is_mcp_method(rpc.method_raw.as_deref().unwrap_or(method))
    }) || rpc.method_raw.as_deref().is_some_and(is_mcp_method)
    {
        Some("mcp")
    } else if rpc.method.as_deref().is_some_and(is_a2a_method)
        || rpc.method_raw.as_deref().is_some_and(is_a2a_method)
    {
        Some("a2a")
    } else if rpc.kind.is_some() {
        Some("jsonrpc")
    } else {
        None
    }
}

fn is_mcp_method(method: &str) -> bool {
    matches!(method, "initialize" | "ping")
        || method.starts_with("completion/")
        || method.starts_with("elicitation/")
        || method.starts_with("logging/")
        || method.starts_with("notifications/")
        || method.starts_with("prompts/")
        || method.starts_with("resources/")
        || method.starts_with("roots/")
        || method.starts_with("sampling/")
        || method.starts_with("tasks/")
        || method.starts_with("tools/")
}

fn is_a2a_method(method: &str) -> bool {
    matches!(
        method,
        "CancelTask"
            | "GetExtendedAgentCard"
            | "GetTask"
            | "ListTasks"
            | "SendMessage"
            | "SendStreamingMessage"
            | "SubscribeToTask"
    )
}

fn first_json_rpc_object(
    value: &serde_json::Value,
) -> Option<&serde_json::Map<String, serde_json::Value>> {
    match value {
        serde_json::Value::Object(obj) => Some(obj),
        serde_json::Value::Array(values) => values.iter().find_map(|item| item.as_object()),
        _ => None,
    }
}

fn json_string(value: Option<&serde_json::Value>) -> Option<String> {
    value.and_then(|value| match value {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        serde_json::Value::Null => Some("null".to_string()),
        _ => None,
    })
}

fn json_f64(value: Option<&serde_json::Value>) -> Option<f64> {
    value.and_then(|value| match value {
        serde_json::Value::Number(value) => value.as_f64(),
        _ => None,
    })
}

fn extract_mcp_fields(value: &serde_json::Value, method: Option<&str>) -> ProtocolSummary {
    let Some(obj) = first_json_rpc_object(value) else {
        return ProtocolSummary::default();
    };
    let params = obj.get("params").and_then(|value| value.as_object());
    let result = obj.get("result").and_then(|value| value.as_object());

    let mut summary = ProtocolSummary {
        mcp_task_id: json_string(
            params
                .and_then(|value| value.get("taskId"))
                .or_else(|| result.and_then(|value| value.get("taskId")))
                .or_else(|| {
                    result
                        .and_then(|value| value.get("task"))
                        .and_then(|value| value.get("taskId"))
                })
                .or_else(|| {
                    result
                        .and_then(|value| value.get("task"))
                        .and_then(|value| value.get("id"))
                }),
        ),
        mcp_progress_token: json_string(params.and_then(|value| value.get("progressToken"))),
        mcp_cursor: json_string(params.and_then(|value| value.get("cursor"))),
        mcp_next_cursor: json_string(result.and_then(|value| value.get("nextCursor"))),
        mcp_list_changed: params
            .and_then(|value| value.get("listChanged"))
            .and_then(|value| value.as_bool())
            .or_else(|| {
                result
                    .and_then(|value| value.get("listChanged"))
                    .and_then(|value| value.as_bool())
            }),
        mcp_resource_uri: json_string(
            params
                .and_then(|value| value.get("uri"))
                .or_else(|| {
                    params
                        .and_then(|value| value.get("resource"))
                        .and_then(|value| value.get("uri"))
                })
                .or_else(|| result.and_then(|value| value.get("uri")))
                .or_else(|| {
                    result
                        .and_then(|value| value.get("contents"))
                        .and_then(|value| value.as_array())
                        .and_then(|value| value.first())
                        .and_then(|value| value.get("uri"))
                }),
        ),
        mcp_tool_is_error: result
            .and_then(|value| value.get("isError"))
            .and_then(|value| value.as_bool()),
        ..ProtocolSummary::default()
    };

    if matches!(method, Some("tools/call")) {
        summary.mcp_tool_name = json_string(params.and_then(|value| value.get("name")));
    }
    if matches!(method, Some("notifications/progress")) {
        summary.mcp_progress = json_f64(params.and_then(|value| value.get("progress")));
        summary.mcp_progress_total = json_f64(params.and_then(|value| value.get("total")));
        summary.mcp_progress_message = params
            .and_then(|value| value.get("message"))
            .and_then(|value| value.as_str())
            .map(ToString::to_string);
    }
    if matches!(method, Some("notifications/message")) {
        summary.mcp_log_level = params
            .and_then(|value| value.get("level"))
            .and_then(|value| value.as_str())
            .map(ToString::to_string);
        summary.mcp_logger = params
            .and_then(|value| value.get("logger"))
            .and_then(|value| value.as_str())
            .map(ToString::to_string);
    }

    summary
}

fn extract_a2a_fields(value: &serde_json::Value) -> ProtocolSummary {
    let Some(obj) = first_json_rpc_object(value) else {
        return ProtocolSummary::default();
    };
    let params = obj.get("params").and_then(|value| value.as_object());
    let result = obj.get("result").and_then(|value| value.as_object());
    let request_message = params
        .and_then(|value| value.get("message"))
        .and_then(|value| value.as_object());
    let response_message = result
        .and_then(|value| value.get("message"))
        .and_then(|value| value.as_object());
    let task = result
        .and_then(|value| value.get("task"))
        .and_then(|value| value.as_object())
        .or_else(|| {
            params
                .and_then(|value| value.get("task"))
                .and_then(|value| value.as_object())
        });

    ProtocolSummary {
        a2a_message_id: request_message
            .and_then(|value| value.get("messageId"))
            .and_then(|value| value.as_str())
            .or_else(|| {
                response_message
                    .and_then(|value| value.get("messageId"))
                    .and_then(|value| value.as_str())
            })
            .map(ToString::to_string),
        a2a_context_id: request_message
            .and_then(|value| value.get("contextId"))
            .and_then(|value| value.as_str())
            .or_else(|| {
                response_message
                    .and_then(|value| value.get("contextId"))
                    .and_then(|value| value.as_str())
            })
            .or_else(|| {
                task.and_then(|value| value.get("contextId"))
                    .and_then(|value| value.as_str())
            })
            .map(ToString::to_string),
        a2a_reference_task_id: request_message
            .and_then(|value| value.get("referenceTaskIds"))
            .and_then(|value| value.as_array())
            .and_then(|value| value.first())
            .and_then(|value| value.as_str())
            .map(ToString::to_string),
        a2a_task_id: task
            .and_then(|value| value.get("id").or_else(|| value.get("taskId")))
            .and_then(|value| value.as_str())
            .or_else(|| {
                params
                    .and_then(|value| value.get("id").or_else(|| value.get("taskId")))
                    .and_then(|value| value.as_str())
            })
            .map(ToString::to_string),
        a2a_task_state: task
            .and_then(|value| value.get("status"))
            .and_then(|value| value.as_object())
            .and_then(|value| value.get("state"))
            .and_then(|value| value.as_str())
            .map(ToString::to_string),
        a2a_artifact_count: task
            .and_then(|value| value.get("artifacts"))
            .and_then(|value| value.as_array())
            .map(|value| value.len() as i64),
        ..ProtocolSummary::default()
    }
}

fn extract_protocol_summary(
    telemetry: &HttpExchangeTelemetryContext,
    body_text: &str,
) -> ProtocolSummary {
    if body_text.trim().is_empty() {
        return ProtocolSummary::default();
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body_text) else {
        return ProtocolSummary::default();
    };

    let rpc = extract_json_rpc_from_value(&value);
    let mut summary = ProtocolSummary {
        protocol: protocol_hint_for_exchange(telemetry, &rpc),
        rpc_kind: rpc.kind,
        rpc_method_raw: rpc.method_raw.clone(),
        rpc_method: rpc.method.clone(),
        rpc_id: rpc.id.clone(),
        rpc_is_notification: rpc.is_notification,
        rpc_error_code: rpc.error_code,
        rpc_error_message: rpc.error_message.clone(),
        request_key: rpc.id.as_ref().map(|id| format!("rpc:{id}")),
        ..ProtocolSummary::default()
    };

    match summary.protocol {
        Some("mcp") => {
            summary.merge_from(&extract_mcp_fields(&value, summary.rpc_method.as_deref()))
        }
        Some("a2a") => summary.merge_from(&extract_a2a_fields(&value)),
        _ => {}
    }

    if summary.request_key.is_none() {
        if let Some(task_id) = summary.mcp_task_id.as_deref() {
            summary.request_key = Some(format!("mcp:task:{task_id}"));
        } else if let Some(task_id) = summary.a2a_task_id.as_deref() {
            summary.request_key = Some(format!("a2a:task:{task_id}"));
        } else if let Some(message_id) = summary.a2a_message_id.as_deref() {
            summary.request_key = Some(format!("a2a:message:{message_id}"));
        }
    }
    if summary.parent_request_key.is_none()
        && let Some(task_id) = summary.a2a_reference_task_id.as_deref()
    {
        summary.parent_request_key = Some(format!("a2a:task:{task_id}"));
    }

    summary
}

struct ParsedSseEvent {
    event: Option<String>,
    id: Option<String>,
    data: String,
}

#[derive(Default)]
struct SseStreamParser {
    pending_line: String,
    event_name: Option<String>,
    event_id: Option<String>,
    data_lines: Vec<String>,
}

impl SseStreamParser {
    fn push_text(&mut self, chunk: &str, is_final: bool) -> Vec<ParsedSseEvent> {
        self.pending_line.push_str(chunk);
        let mut events = Vec::new();

        while let Some(index) = self.pending_line.find('\n') {
            let mut line = self.pending_line[..index].to_string();
            self.pending_line.drain(..=index);
            if line.ends_with('\r') {
                line.pop();
            }
            self.process_line(line.as_str(), &mut events);
        }

        if is_final {
            if !self.pending_line.is_empty() {
                let mut line = std::mem::take(&mut self.pending_line);
                if line.ends_with('\r') {
                    line.pop();
                }
                self.process_line(line.as_str(), &mut events);
            }
            self.flush_event(&mut events);
        }

        events
    }

    fn process_line(&mut self, line: &str, events: &mut Vec<ParsedSseEvent>) {
        if line.is_empty() {
            self.flush_event(events);
            return;
        }
        if line.starts_with(':') {
            return;
        }
        let (field, value) = match line.split_once(':') {
            Some((field, rest)) => (field, rest.strip_prefix(' ').unwrap_or(rest)),
            None => (line, ""),
        };
        match field {
            "event" => self.event_name = Some(value.to_string()),
            "id" => self.event_id = Some(value.to_string()),
            "data" => self.data_lines.push(value.to_string()),
            _ => {}
        }
    }

    fn flush_event(&mut self, events: &mut Vec<ParsedSseEvent>) {
        if !self.data_lines.is_empty() || self.event_name.is_some() || self.event_id.is_some() {
            events.push(ParsedSseEvent {
                event: self.event_name.take(),
                id: self.event_id.take(),
                data: self.data_lines.join("\n"),
            });
            self.data_lines.clear();
        }
    }
}

#[cfg(test)]
fn parse_sse_events(body_text: &str) -> Vec<ParsedSseEvent> {
    let mut parser = SseStreamParser::default();
    parser.push_text(body_text, true)
}

#[derive(Clone, Copy, Debug)]
enum BodyCaptureDisposition {
    Capture,
    Omit,
}

fn body_capture_disposition(content_type: Option<&str>) -> BodyCaptureDisposition {
    let Some(content_type) = content_type else {
        return BodyCaptureDisposition::Capture;
    };
    let content_type = content_type.trim().to_ascii_lowercase();
    if content_type.starts_with("image/")
        || content_type.starts_with("audio/")
        || content_type.starts_with("video/")
        || content_type.starts_with("application/octet-stream")
    {
        BodyCaptureDisposition::Omit
    } else {
        BodyCaptureDisposition::Capture
    }
}

fn is_sse_content_type(content_type: Option<&str>) -> bool {
    content_type
        .map(|value| value.trim().to_ascii_lowercase())
        .is_some_and(|value| value.starts_with("text/event-stream"))
}

struct CapturedBodyMetadata<'a> {
    total_bytes: usize,
    truncated: bool,
    omitted: bool,
    content_type: Option<&'a str>,
    content_encoding: Option<&'a str>,
}

fn emit_sse_event(
    span: &tracing::Span,
    telemetry: &HttpExchangeTelemetryContext,
    sse_event: ParsedSseEvent,
) {
    let summary = extract_protocol_summary(telemetry, &sse_event.data);
    let message = format!(
        "{} [stream event]",
        exchange_message(telemetry, HttpLifecyclePart::Response, &summary)
    );
    let mut extra_attributes = Vec::with_capacity(3);
    push_nonempty_log_attr(
        &mut extra_attributes,
        "amber_sse_event",
        sse_event.event.as_deref().unwrap_or(""),
    );
    push_nonempty_log_attr(
        &mut extra_attributes,
        "amber_sse_id",
        sse_event.id.as_deref().unwrap_or(""),
    );
    push_nonempty_log_attr(
        &mut extra_attributes,
        "amber_sse_data",
        sse_event.data.as_str(),
    );
    emit_binding_log(
        span,
        telemetry,
        &summary,
        BindingLogSpec {
            level: Severity::Info,
            part: HttpLifecyclePart::Response,
            step: "stream_event",
            transport: "sse",
            event_name: "amber.binding.sse",
            message,
            extra_attributes,
        },
    );
}

fn emit_body_event(
    span: &tracing::Span,
    telemetry: &HttpExchangeTelemetryContext,
    part: HttpLifecyclePart,
    event_name: &'static str,
    captured: &[u8],
    metadata: CapturedBodyMetadata<'_>,
) {
    let body_utf8 = !metadata.omitted && std::str::from_utf8(captured).is_ok();
    let body_text = if metadata.omitted || !body_utf8 {
        ""
    } else {
        std::str::from_utf8(captured).unwrap_or("")
    };
    let summary = if body_utf8 {
        extract_protocol_summary(telemetry, body_text)
    } else {
        ProtocolSummary::default()
    };
    let message = format!("{} [body]", exchange_message(telemetry, part, &summary));
    let mut extra_attributes = Vec::with_capacity(7);
    if metadata.total_bytes > 0 {
        push_log_attr(
            &mut extra_attributes,
            "amber_body_size_bytes",
            i64::try_from(metadata.total_bytes).unwrap_or(i64::MAX),
        );
    }
    push_true_log_attr(
        &mut extra_attributes,
        "amber_body_truncated",
        metadata.truncated,
    );
    push_true_log_attr(
        &mut extra_attributes,
        "amber_body_omitted",
        metadata.omitted,
    );
    if !body_utf8 {
        push_log_attr(&mut extra_attributes, "amber_body_utf8", false);
    }
    push_nonempty_log_attr(
        &mut extra_attributes,
        "amber_body_content_type",
        metadata.content_type.unwrap_or(""),
    );
    push_nonempty_log_attr(
        &mut extra_attributes,
        "amber_body_content_encoding",
        metadata.content_encoding.unwrap_or(""),
    );
    push_nonempty_log_attr(&mut extra_attributes, "amber_body_text", body_text);
    emit_binding_log(
        span,
        telemetry,
        &summary,
        BindingLogSpec {
            level: Severity::Info,
            part,
            step: "body",
            transport: "http",
            event_name,
            message,
            extra_attributes,
        },
    );
}

struct CapturedBodyCompletion {
    span: tracing::Span,
    telemetry: HttpExchangeTelemetryContext,
    part: HttpLifecyclePart,
    event_name: &'static str,
    disposition: BodyCaptureDisposition,
    content_type: Option<String>,
    content_encoding: Option<String>,
}

fn emit_captured_body_completion(
    completion: &CapturedBodyCompletion,
    captured: &[u8],
    total_bytes: usize,
    truncated: bool,
    sse_parser: &mut Option<SseStreamParser>,
) {
    if let Some(mut parser) = sse_parser.take() {
        for sse_event in parser.push_text("", true) {
            emit_sse_event(&completion.span, &completion.telemetry, sse_event);
        }
    }
    let omitted = matches!(completion.disposition, BodyCaptureDisposition::Omit);
    emit_body_event(
        &completion.span,
        &completion.telemetry,
        completion.part,
        completion.event_name,
        captured,
        CapturedBodyMetadata {
            total_bytes,
            truncated,
            omitted,
            content_type: completion.content_type.as_deref(),
            content_encoding: completion.content_encoding.as_deref(),
        },
    );
}

fn capture_box_body(
    body: BoxBody,
    span: tracing::Span,
    telemetry: HttpExchangeTelemetryContext,
    part: HttpLifecyclePart,
    event_name: &'static str,
    content_type: Option<String>,
    content_encoding: Option<String>,
) -> BoxBody {
    let disposition = body_capture_disposition(content_type.as_deref());
    let sse_enabled = matches!(disposition, BodyCaptureDisposition::Capture)
        && is_sse_content_type(content_type.as_deref());
    let expected_bytes = body
        .size_hint()
        .exact()
        .and_then(|bytes| usize::try_from(bytes).ok());
    let source = BodyStream::new(body);
    let captured = Vec::new();
    let total_bytes: usize = 0;
    let truncated = false;
    let sse_parser = sse_enabled.then(SseStreamParser::default);
    let body_event_emitted = false;
    let completion = CapturedBodyCompletion {
        span: span.clone(),
        telemetry: telemetry.clone(),
        part,
        event_name,
        disposition,
        content_type: content_type.clone(),
        content_encoding: content_encoding.clone(),
    };

    let stream = futures::stream::try_unfold(
        (
            source,
            span,
            telemetry,
            disposition,
            content_type,
            content_encoding,
            captured,
            total_bytes,
            truncated,
            sse_parser,
            body_event_emitted,
            expected_bytes,
            completion,
        ),
        move |(
            mut source,
            span,
            telemetry,
            disposition,
            content_type,
            content_encoding,
            mut captured,
            mut total_bytes,
            mut truncated,
            mut sse_parser,
            mut body_event_emitted,
            expected_bytes,
            completion,
        )| async move {
            match source.next().await {
                Some(Ok(frame)) => {
                    let frame_was_final = source.is_end_stream();
                    match frame.into_data() {
                        Ok(chunk) => {
                            total_bytes = total_bytes.saturating_add(chunk.len());
                            if matches!(disposition, BodyCaptureDisposition::Capture) && !truncated
                            {
                                let remaining = DEFAULT_HTTP_BODY_CAPTURE_LIMIT_BYTES
                                    .saturating_sub(captured.len());
                                if remaining == 0 {
                                    truncated = true;
                                } else if chunk.len() <= remaining {
                                    captured.extend_from_slice(&chunk);
                                } else {
                                    captured.extend_from_slice(&chunk[..remaining]);
                                    truncated = true;
                                }
                            }
                            if let Some(parser) = sse_parser.as_mut() {
                                let chunk_text = String::from_utf8_lossy(chunk.as_ref());
                                for sse_event in parser.push_text(chunk_text.as_ref(), false) {
                                    emit_sse_event(&span, &telemetry, sse_event);
                                }
                            }
                            let body_complete = frame_was_final
                                || expected_bytes.is_some_and(|bytes| total_bytes >= bytes);
                            if body_complete && !body_event_emitted {
                                emit_captured_body_completion(
                                    &completion,
                                    &captured,
                                    total_bytes,
                                    truncated,
                                    &mut sse_parser,
                                );
                                body_event_emitted = true;
                            }

                            let next_state = (
                                source,
                                span,
                                telemetry,
                                disposition,
                                content_type,
                                content_encoding,
                                captured,
                                total_bytes,
                                truncated,
                                sse_parser,
                                body_event_emitted,
                                expected_bytes,
                                completion,
                            );
                            Ok(Some((Frame::data(chunk), next_state)))
                        }
                        Err(frame) => {
                            let body_complete = frame_was_final
                                || expected_bytes.is_some_and(|bytes| total_bytes >= bytes);
                            if body_complete && !body_event_emitted {
                                emit_captured_body_completion(
                                    &completion,
                                    &captured,
                                    total_bytes,
                                    truncated,
                                    &mut sse_parser,
                                );
                                body_event_emitted = true;
                            }
                            let next_state = (
                                source,
                                span,
                                telemetry,
                                disposition,
                                content_type,
                                content_encoding,
                                captured,
                                total_bytes,
                                truncated,
                                sse_parser,
                                body_event_emitted,
                                expected_bytes,
                                completion,
                            );
                            Ok(Some((frame, next_state)))
                        }
                    }
                }
                Some(Err(err)) => {
                    let message = match part {
                        HttpLifecyclePart::Request => {
                            format!("{} request body stream error", telemetry.local_role())
                        }
                        HttpLifecyclePart::Response => {
                            format!("{} response body stream error", telemetry.local_role())
                        }
                    };
                    let summary = telemetry.summary_snapshot();
                    let mut extra_attributes = Vec::with_capacity(1);
                    push_log_attr(&mut extra_attributes, "amber_body_error", err.to_string());
                    emit_binding_log(
                        &span,
                        &telemetry,
                        &summary,
                        BindingLogSpec {
                            level: Severity::Warn,
                            part,
                            step: "body",
                            transport: if sse_enabled { "sse" } else { "http" },
                            event_name,
                            message,
                            extra_attributes,
                        },
                    );
                    Err(err)
                }
                None => {
                    if !body_event_emitted {
                        emit_captured_body_completion(
                            &completion,
                            &captured,
                            total_bytes,
                            truncated,
                            &mut sse_parser,
                        );
                    }
                    Ok(None)
                }
            }
        },
    );

    http_body_util::BodyExt::map_err(StreamBody::new(stream), |err| err).boxed()
}

async fn proxy_local_http_request(
    state: LocalHttpProxyState,
    req: Request<Incoming>,
) -> Response<BoxBody> {
    let emit_telemetry = state.labels.emit_telemetry;
    let telemetry = HttpExchangeTelemetryContext::new(RewriteFlow::Inbound, &state.labels);
    let span = if emit_telemetry {
        start_http_exchange_span(&telemetry, &req)
    } else {
        tracing::Span::none()
    };
    let instrument_span = span.clone();
    let status_span = span.clone();
    let status_telemetry = telemetry.clone();

    let response = async move {
        let request_is_agent_card = a2a::is_agent_card_path(req.uri().path());
        let mut parts = req.into_parts();
        if emit_telemetry {
            emit_headers_event(
                &span,
                &telemetry,
                HttpLifecyclePart::Request,
                "amber.binding.request.headers",
                parts
                    .0
                    .headers
                    .get(header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                parts
                    .0
                    .headers
                    .get(header::CONTENT_ENCODING)
                    .and_then(|value| value.to_str().ok()),
                &parts.0.headers,
            );
        }
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

        let request_body = if request_body_collect
            && is_identity_or_absent_content_encoding(&parts.0.headers)
        {
            let mut body = match parts.1.collect().await {
                Ok(collected) => collected.to_bytes().to_vec(),
                Err(err) => {
                    let error_detail = err.to_string();
                    tracing::warn!(
                        target: "amber.internal",
                        "router request body read failed: {error_detail}"
                    );
                    emit_binding_failure_event(
                        &span,
                        &telemetry,
                        StatusCode::BAD_GATEWAY,
                        "upstream request read failed",
                        Some(error_detail),
                    );
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
            let content_type = parts
                .0
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_string());
            let content_encoding = parts
                .0
                .headers
                .get(header::CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_string());
            let omitted = matches!(
                body_capture_disposition(content_type.as_deref()),
                BodyCaptureDisposition::Omit
            );
            if emit_telemetry {
                emit_body_event(
                    &span,
                    &telemetry,
                    HttpLifecyclePart::Request,
                    "amber.binding.request.body",
                    &body,
                    CapturedBodyMetadata {
                        total_bytes: body.len(),
                        truncated: false,
                        omitted,
                        content_type: content_type.as_deref(),
                        content_encoding: content_encoding.as_deref(),
                    },
                );
            }
            Full::new(Bytes::from(body))
                .map_err(|never| match never {})
                .boxed()
        } else {
            if request_body_collect {
                tracing::warn!(
                    target: "amber.internal",
                    "unsupported Content-Encoding on request body; skipping body-aware \
                     request                      rewrites"
                );
            }
            if let Some(response) = apply_request_filters(&matching_plugins, &ctx, &parts.0, None) {
                return response;
            }
            let encoding_supported = is_identity_or_absent_content_encoding(&parts.0.headers);
            let body = if request_stream_rewriters.is_empty() || !encoding_supported {
                if !request_stream_rewriters.is_empty() && !encoding_supported {
                    tracing::warn!(
                        target: "amber.internal",
                        "unsupported Content-Encoding on request body; skipping request \
                         stream                          rewrites"
                    );
                }
                parts.1.boxed()
            } else {
                strip_request_body_validators(&mut parts.0.headers);
                parts.0.headers.remove(header::CONTENT_LENGTH);
                rewrite_stream_body(parts.1, request_stream_rewriters)
            };
            if emit_telemetry {
                capture_box_body(
                    body,
                    span.clone(),
                    telemetry.clone(),
                    HttpLifecyclePart::Request,
                    "amber.binding.request.body",
                    parts
                        .0
                        .headers
                        .get(header::CONTENT_TYPE)
                        .and_then(|value| value.to_str().ok())
                        .map(|value| value.to_string()),
                    parts
                        .0
                        .headers
                        .get(header::CONTENT_ENCODING)
                        .and_then(|value| value.to_str().ok())
                        .map(|value| value.to_string()),
                )
            } else {
                body
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
        if emit_telemetry {
            inject_trace_context(&span, &mut request_parts.headers);
        }
        let upstream_uri = request_parts.uri.to_string();

        let proxied = Request::from_parts(request_parts, request_body);
        if response_body_collect {
            let response = match Decompression::new(state.client.clone())
                .oneshot(proxied)
                .await
            {
                Ok(resp) => resp,
                Err(err) => {
                    let error_detail = err.to_string();
                    tracing::warn!(
                        target: "amber.internal",
                        upstream_uri = %upstream_uri,
                        error = %error_detail,
                        "router request failed"
                    );
                    emit_binding_failure_event(
                        &span,
                        &telemetry,
                        StatusCode::BAD_GATEWAY,
                        "upstream request failed",
                        Some(error_detail),
                    );
                    return error_response(StatusCode::BAD_GATEWAY, "upstream request failed");
                }
            };
            let (mut response_parts, response_body) = response.into_parts();
            let mut body = match response_body.collect().await {
                Ok(collected) => collected.to_bytes().to_vec(),
                Err(err) => {
                    let error_detail = err.to_string();
                    tracing::warn!(
                        target: "amber.internal",
                        "router response body read failed: {error_detail}"
                    );
                    emit_binding_failure_event(
                        &span,
                        &telemetry,
                        StatusCode::BAD_GATEWAY,
                        "upstream response read failed",
                        Some(error_detail),
                    );
                    return error_response(
                        StatusCode::BAD_GATEWAY,
                        "upstream response read failed",
                    );
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
            if emit_telemetry {
                emit_headers_event(
                    &span,
                    &telemetry,
                    HttpLifecyclePart::Response,
                    "amber.binding.response.headers",
                    response_parts
                        .headers
                        .get(header::CONTENT_TYPE)
                        .and_then(|value| value.to_str().ok()),
                    response_parts
                        .headers
                        .get(header::CONTENT_ENCODING)
                        .and_then(|value| value.to_str().ok()),
                    &response_parts.headers,
                );
            }
            response_parts
                .headers
                .insert(header::CONTENT_LENGTH, content_length_header(body.len()));
            let content_type = response_parts
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_string());
            let content_encoding = response_parts
                .headers
                .get(header::CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_string());
            let omitted = matches!(
                body_capture_disposition(content_type.as_deref()),
                BodyCaptureDisposition::Omit
            );
            if emit_telemetry {
                emit_body_event(
                    &span,
                    &telemetry,
                    HttpLifecyclePart::Response,
                    "amber.binding.response.body",
                    &body,
                    CapturedBodyMetadata {
                        total_bytes: body.len(),
                        truncated: false,
                        omitted,
                        content_type: content_type.as_deref(),
                        content_encoding: content_encoding.as_deref(),
                    },
                );
            }
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
                let error_detail = err.to_string();
                tracing::warn!(
                    target: "amber.internal",
                    upstream_uri = %upstream_uri,
                    error = %error_detail,
                    "router request failed"
                );
                emit_binding_failure_event(
                    &span,
                    &telemetry,
                    StatusCode::BAD_GATEWAY,
                    "upstream request failed",
                    Some(error_detail),
                );
                return error_response(StatusCode::BAD_GATEWAY, "upstream request failed");
            }
        };
        let (mut response_parts, response_body) = response.into_parts();
        if emit_telemetry {
            emit_headers_event(
                &span,
                &telemetry,
                HttpLifecyclePart::Response,
                "amber.binding.response.headers",
                response_parts
                    .headers
                    .get(header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                response_parts
                    .headers
                    .get(header::CONTENT_ENCODING)
                    .and_then(|value| value.to_str().ok()),
                &response_parts.headers,
            );
        }
        if let Some(response) =
            apply_response_filters(&matching_plugins, &ctx, &response_parts, None)
        {
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
        let response_body = if emit_telemetry {
            capture_box_body(
                response_body,
                span,
                telemetry,
                HttpLifecyclePart::Response,
                "amber.binding.response.body",
                response_parts
                    .headers
                    .get(header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .map(|value| value.to_string()),
                response_parts
                    .headers
                    .get(header::CONTENT_ENCODING)
                    .and_then(|value| value.to_str().ok())
                    .map(|value| value.to_string()),
            )
        } else {
            response_body
        };
        Response::from_parts(response_parts, response_body)
    }
    .instrument(instrument_span)
    .await;
    if emit_telemetry {
        finalize_http_exchange_response(&status_span, &status_telemetry, response)
    } else {
        response
    }
}

async fn proxy_local_http_to_noise(
    session: &mut NoiseSession,
    route_id: Arc<str>,
    stream: tokio::net::TcpStream,
    plugins: Arc<[Arc<dyn HttpExchangePlugin>]>,
    labels: HttpExchangeLabels,
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
            tracing::warn!(target: "amber.internal", "outbound upstream connection failed: {err}");
        }
    });

    let state = OutboundHttpProxyState {
        upstream: Arc::new(Mutex::new(sender)),
        plugins,
        route_id,
        labels,
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

async fn proxy_http_request_to_noise(
    flow: RewriteFlow,
    state: OutboundHttpProxyState,
    req: Request<Incoming>,
) -> Response<BoxBody> {
    let telemetry = HttpExchangeTelemetryContext::new(flow, &state.labels);
    let span = start_http_exchange_span(&telemetry, &req);
    let instrument_span = span.clone();
    let status_span = span.clone();
    let status_telemetry = telemetry.clone();

    let response = async move {
        let request_is_agent_card = a2a::is_agent_card_path(req.uri().path());
        let mut parts = req.into_parts();
        emit_headers_event(
            &span,
            &telemetry,
            HttpLifecyclePart::Request,
            "amber.binding.request.headers",
            parts
                .0
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            parts
                .0
                .headers
                .get(header::CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok()),
            &parts.0.headers,
        );
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
            flow,
            request_is_agent_card,
            route_id: state.route_id.clone(),
        };
        let request_stream_rewriters = if request_body_collect {
            Vec::new()
        } else {
            collect_request_stream_rewriters(&matching_plugins, &ctx, &parts.0)
        };

        let request_body = if request_body_collect
            && is_identity_or_absent_content_encoding(&parts.0.headers)
        {
            let mut body = match parts.1.collect().await {
                Ok(collected) => collected.to_bytes().to_vec(),
                Err(err) => {
                    let error_detail = err.to_string();
                    tracing::warn!(
                        target: "amber.internal",
                        "router request body read failed: {error_detail}"
                    );
                    emit_binding_failure_event(
                        &span,
                        &telemetry,
                        StatusCode::BAD_GATEWAY,
                        "upstream request read failed",
                        Some(error_detail),
                    );
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
            let content_type = parts
                .0
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_string());
            let content_encoding = parts
                .0
                .headers
                .get(header::CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_string());
            let omitted = matches!(
                body_capture_disposition(content_type.as_deref()),
                BodyCaptureDisposition::Omit
            );
            emit_body_event(
                &span,
                &telemetry,
                HttpLifecyclePart::Request,
                "amber.binding.request.body",
                &body,
                CapturedBodyMetadata {
                    total_bytes: body.len(),
                    truncated: false,
                    omitted,
                    content_type: content_type.as_deref(),
                    content_encoding: content_encoding.as_deref(),
                },
            );
            Full::new(Bytes::from(body))
                .map_err(|never| match never {})
                .boxed()
        } else {
            if request_body_collect {
                tracing::warn!(
                    target: "amber.internal",
                    "unsupported Content-Encoding on request body; skipping body-aware request \
                     rewrites"
                );
            }
            if let Some(response) = apply_request_filters(&matching_plugins, &ctx, &parts.0, None) {
                return response;
            }
            let encoding_supported = is_identity_or_absent_content_encoding(&parts.0.headers);
            let body = if request_stream_rewriters.is_empty() || !encoding_supported {
                if !request_stream_rewriters.is_empty() && !encoding_supported {
                    tracing::warn!(
                        target: "amber.internal",
                        "unsupported Content-Encoding on request body; skipping request stream \
                         rewrites"
                    );
                }
                parts.1.boxed()
            } else {
                strip_request_body_validators(&mut parts.0.headers);
                parts.0.headers.remove(header::CONTENT_LENGTH);
                rewrite_stream_body(parts.1, request_stream_rewriters)
            };
            capture_box_body(
                body,
                span.clone(),
                telemetry.clone(),
                HttpLifecyclePart::Request,
                "amber.binding.request.body",
                parts
                    .0
                    .headers
                    .get(header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .map(|value| value.to_string()),
                parts
                    .0
                    .headers
                    .get(header::CONTENT_ENCODING)
                    .and_then(|value| value.to_str().ok())
                    .map(|value| value.to_string()),
            )
        };

        let mut request_parts = parts.0;
        if response_body_collect || !matching_plugins.is_empty() {
            request_parts.headers.remove(header::ACCEPT_ENCODING);
        }
        let host_header = outgoing_host_header(&request_parts.uri, &request_parts.headers);
        sanitize_request_headers(&mut request_parts.headers, host_header.as_str());
        inject_trace_context(&span, &mut request_parts.headers);
        let upstream_uri = request_parts.uri.to_string();

        let proxied = Request::from_parts(request_parts, request_body);
        let response = {
            let mut upstream = state.upstream.lock().await;
            match send_http1_request(&mut upstream, proxied).await {
                Ok(resp) => resp,
                Err(err) => {
                    let error_detail = err.to_string();
                    tracing::warn!(
                        target: "amber.internal",
                        upstream_uri = %upstream_uri,
                        error = %error_detail,
                        "router request failed"
                    );
                    emit_binding_failure_event(
                        &span,
                        &telemetry,
                        StatusCode::BAD_GATEWAY,
                        "upstream request failed",
                        Some(error_detail),
                    );
                    return error_response(StatusCode::BAD_GATEWAY, "upstream request failed");
                }
            }
        };

        if response_body_collect {
            let (mut response_parts, response_body) = response.into_parts();
            let mut body = match response_body.collect().await {
                Ok(collected) => collected.to_bytes().to_vec(),
                Err(err) => {
                    let error_detail = err.to_string();
                    tracing::warn!(
                        target: "amber.internal",
                        "router response body read failed: {error_detail}"
                    );
                    emit_binding_failure_event(
                        &span,
                        &telemetry,
                        StatusCode::BAD_GATEWAY,
                        "upstream response read failed",
                        Some(error_detail),
                    );
                    return error_response(
                        StatusCode::BAD_GATEWAY,
                        "upstream response read failed",
                    );
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
            emit_headers_event(
                &span,
                &telemetry,
                HttpLifecyclePart::Response,
                "amber.binding.response.headers",
                response_parts
                    .headers
                    .get(header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                response_parts
                    .headers
                    .get(header::CONTENT_ENCODING)
                    .and_then(|value| value.to_str().ok()),
                &response_parts.headers,
            );
            response_parts
                .headers
                .insert(header::CONTENT_LENGTH, content_length_header(body.len()));
            let content_type = response_parts
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_string());
            let content_encoding = response_parts
                .headers
                .get(header::CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_string());
            let omitted = matches!(
                body_capture_disposition(content_type.as_deref()),
                BodyCaptureDisposition::Omit
            );
            emit_body_event(
                &span,
                &telemetry,
                HttpLifecyclePart::Response,
                "amber.binding.response.body",
                &body,
                CapturedBodyMetadata {
                    total_bytes: body.len(),
                    truncated: false,
                    omitted,
                    content_type: content_type.as_deref(),
                    content_encoding: content_encoding.as_deref(),
                },
            );
            return Response::from_parts(
                response_parts,
                Full::new(Bytes::from(body))
                    .map_err(|never| match never {})
                    .boxed(),
            );
        }

        let (mut response_parts, response_body) = response.into_parts();
        emit_headers_event(
            &span,
            &telemetry,
            HttpLifecyclePart::Response,
            "amber.binding.response.headers",
            response_parts
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            response_parts
                .headers
                .get(header::CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok()),
            &response_parts.headers,
        );
        if let Some(response) =
            apply_response_filters(&matching_plugins, &ctx, &response_parts, None)
        {
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
        let response_body = capture_box_body(
            response_body,
            span,
            telemetry,
            HttpLifecyclePart::Response,
            "amber.binding.response.body",
            response_parts
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_string()),
            response_parts
                .headers
                .get(header::CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_string()),
        );
        Response::from_parts(response_parts, response_body)
    }
    .instrument(instrument_span)
    .await;
    finalize_http_exchange_response(&status_span, &status_telemetry, response)
}

async fn proxy_http_request(state: HttpProxyState, req: Request<Incoming>) -> Response<BoxBody> {
    let telemetry = HttpExchangeTelemetryContext::new(RewriteFlow::Outbound, &state.labels);
    let span = start_http_exchange_span(&telemetry, &req);
    let instrument_span = span.clone();
    let status_span = span.clone();
    let status_telemetry = telemetry.clone();

    let response = async move {
        let resolved_target = match resolve_http_external_target(&state, req.uri()).await {
            Ok(target) => target,
            Err(err) => {
                clear_mesh_http_upstream(&state).await;
                return err;
            }
        };

        let mut parts = req.into_parts();
        emit_headers_event(
            &span,
            &telemetry,
            HttpLifecyclePart::Request,
            "amber.binding.request.headers",
            parts
                .0
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            parts
                .0
                .headers
                .get(header::CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok()),
            &parts.0.headers,
        );
        let host_header = match configure_http_external_request(&mut parts.0, &resolved_target) {
            Ok(host_header) => host_header,
            Err(err) => {
                clear_mesh_http_upstream(&state).await;
                return err;
            }
        };

        sanitize_request_headers(&mut parts.0.headers, &host_header);
        inject_trace_context(&span, &mut parts.0.headers);

        let request_body = capture_box_body(
            parts.1.boxed(),
            span.clone(),
            telemetry.clone(),
            HttpLifecyclePart::Request,
            "amber.binding.request.body",
            parts
                .0
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_string()),
            parts
                .0
                .headers
                .get(header::CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_string()),
        );
        let proxied = Request::from_parts(parts.0, request_body);
        let upstream_uri = proxied.uri().to_string();
        let external_target = match &resolved_target {
            ResolvedHttpExternalTarget::Http(url) => url.as_str().to_string(),
            ResolvedHttpExternalTarget::Mesh { target_url, .. } => target_url.clone(),
        };

        let response =
            match send_request_to_http_external_target(&state, &resolved_target, proxied).await {
                Ok(resp) => resp,
                Err(err) => {
                    let error_detail = err.to_string();
                    tracing::warn!(
                        target: "amber.internal",
                        upstream_uri = %upstream_uri,
                        external_target = %external_target,
                        error = %error_detail,
                        "router request failed"
                    );
                    emit_binding_failure_event(
                        &span,
                        &telemetry,
                        StatusCode::BAD_GATEWAY,
                        "upstream request failed",
                        Some(error_detail),
                    );
                    return error_response(StatusCode::BAD_GATEWAY, "upstream request failed");
                }
            };

        let mut parts = response.into_parts();
        emit_headers_event(
            &span,
            &telemetry,
            HttpLifecyclePart::Response,
            "amber.binding.response.headers",
            parts
                .0
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            parts
                .0
                .headers
                .get(header::CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok()),
            &parts.0.headers,
        );
        sanitize_response_headers(&mut parts.0.headers);
        let body = capture_box_body(
            parts.1.boxed(),
            span,
            telemetry,
            HttpLifecyclePart::Response,
            "amber.binding.response.body",
            parts
                .0
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_string()),
            parts
                .0
                .headers
                .get(header::CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_string()),
        );
        Response::from_parts(parts.0, body)
    }
    .instrument(instrument_span)
    .await;
    finalize_http_exchange_response(&status_span, &status_telemetry, response)
}

#[allow(clippy::result_large_err)]
fn configure_http_external_request(
    request_parts: &mut http::request::Parts,
    target: &ResolvedHttpExternalTarget,
) -> Result<String, Response<BoxBody>> {
    match target {
        ResolvedHttpExternalTarget::Http(target_url) => {
            let Some(host) = target_url.host_str() else {
                return Err(error_response(
                    StatusCode::BAD_GATEWAY,
                    "target url missing host",
                ));
            };
            request_parts.uri = Uri::try_from(target_url.as_str())
                .map_err(|_| error_response(StatusCode::BAD_GATEWAY, "invalid target url"))?;
            Ok(match target_url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            })
        }
        ResolvedHttpExternalTarget::Mesh { .. } => Ok(outgoing_host_header(
            &request_parts.uri,
            &request_parts.headers,
        )),
    }
}

async fn send_request_to_http_external_target(
    state: &HttpProxyState,
    target: &ResolvedHttpExternalTarget,
    request: Request<BoxBody>,
) -> Result<Response<Incoming>, String> {
    match target {
        ResolvedHttpExternalTarget::Http(_) => {
            clear_mesh_http_upstream(state).await;
            state
                .client
                .request(request)
                .await
                .map_err(|err| err.to_string())
        }
        ResolvedHttpExternalTarget::Mesh { target_url, mesh } => {
            send_request_to_mesh_http_upstream(state, target_url, mesh, request).await
        }
    }
}

async fn clear_mesh_http_upstream(state: &HttpProxyState) {
    state.mesh_upstream.lock().await.take();
}

async fn send_http1_request(
    sender: &mut client_http1::SendRequest<BoxBody>,
    request: Request<BoxBody>,
) -> hyper::Result<Response<Incoming>> {
    sender.ready().await?;
    sender.send_request(request).await
}

async fn send_request_to_mesh_http_upstream(
    state: &HttpProxyState,
    target_url: &str,
    mesh: &MeshExternalTarget,
    request: Request<BoxBody>,
) -> Result<Response<Incoming>, String> {
    let mut upstream = state.mesh_upstream.lock().await;
    if !upstream
        .as_ref()
        .is_some_and(|cached| cached.is_reusable_for(target_url))
    {
        *upstream = Some(
            connect_mesh_http_upstream(
                target_url.to_string(),
                mesh,
                &state.target.name,
                state.config.as_ref(),
            )
            .await
            .map_err(|err| err.to_string())?,
        );
    }

    let response = {
        let cached = upstream
            .as_mut()
            .expect("mesh upstream must exist after initialization");
        send_http1_request(&mut cached.sender, request).await
    };
    if response.is_err() {
        upstream.take();
    }
    response.map_err(|err| err.to_string())
}

async fn connect_mesh_http_upstream(
    target_url: String,
    mesh: &MeshExternalTarget,
    capability: &str,
    config: &MeshConfig,
) -> Result<MeshHttpUpstream, RouterError> {
    let mut outbound =
        connect_noise_with_key(&mesh.peer_addr, &mesh.peer_id, mesh.peer_key, config).await?;
    let open = OpenFrame {
        route_id: component_route_id(&mesh.peer_id, capability, MeshProtocol::Http),
        capability: capability.to_string(),
        protocol: MeshProtocol::Http,
        slot: None,
        capability_kind: None,
        capability_profile: None,
    };
    outbound.send_open(&open).await?;

    let (local, remote) = duplex(64 * 1024);
    let bridge_task =
        tokio::spawn(async move { proxy_noise_to_plain(&mut outbound, remote).await });
    let (sender, conn) = client_http1::handshake(TokioIo::new(local))
        .await
        .map_err(|err| {
            RouterError::Transport(format!("external mesh upstream handshake failed: {err}"))
        })?;
    let conn_task = tokio::spawn(async move {
        if let Err(err) = conn.await {
            tracing::warn!(
                target: "amber.internal",
                "external mesh upstream connection failed: {err}"
            );
        }
    });

    Ok(MeshHttpUpstream {
        target_url,
        sender,
        conn_task,
        bridge_task,
    })
}

async fn proxy_outbound_http_request(
    state: OutboundHttpProxyState,
    req: Request<Incoming>,
) -> Response<BoxBody> {
    proxy_http_request_to_noise(RewriteFlow::Outbound, state, req).await
}

async fn proxy_inbound_http_request_to_noise(
    state: OutboundHttpProxyState,
    req: Request<Incoming>,
) -> Response<BoxBody> {
    proxy_http_request_to_noise(RewriteFlow::Inbound, state, req).await
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
async fn resolve_http_external_target(
    state: &HttpProxyState,
    uri: &Uri,
) -> Result<ResolvedHttpExternalTarget, Response<BoxBody>> {
    let override_url = {
        let overrides = state.external_overrides.read().await;
        overrides.get(&state.target.name).cloned()
    };
    let resolved =
        resolve_http_external_target_with_override(&state.target, override_url.as_deref(), uri)?;
    if let ResolvedHttpExternalTarget::Http(url) = &resolved {
        let Some(host) = url.host_str() else {
            return Err(error_response(
                StatusCode::BAD_GATEWAY,
                "external slot url missing host",
            ));
        };
        let Some(port) = url.port_or_known_default() else {
            return Err(error_response(
                StatusCode::BAD_GATEWAY,
                "external slot url missing port",
            ));
        };
        validate_external_host(host, port)
            .await
            .map_err(|err| error_response(StatusCode::BAD_GATEWAY, &err))?;
    }
    Ok(resolved)
}

#[allow(clippy::result_large_err)]
fn resolve_http_external_target_with_override(
    target: &ExternalTarget,
    override_url: Option<&str>,
    uri: &Uri,
) -> Result<ResolvedHttpExternalTarget, Response<BoxBody>> {
    let url = configured_external_url(target, override_url).ok_or_else(|| {
        error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &external_slot_not_configured_message(target),
        )
    })?;
    if url.starts_with("mesh://") {
        let mesh = parse_mesh_external(&url).map_err(|err| {
            error_response(
                StatusCode::BAD_GATEWAY,
                &format!("external slot url is invalid: {err}"),
            )
        })?;
        return Ok(ResolvedHttpExternalTarget::Mesh {
            target_url: url,
            mesh,
        });
    }

    let base = Url::parse(&url).map_err(|err| {
        error_response(
            StatusCode::BAD_GATEWAY,
            &format!("external slot url is invalid: {err}"),
        )
    })?;

    if !is_http_scheme(&base) {
        return Err(error_response(
            StatusCode::BAD_GATEWAY,
            "external slot url must be http/https",
        ));
    }
    let Some(host) = base.host_str() else {
        return Err(error_response(
            StatusCode::BAD_GATEWAY,
            "external slot url missing host",
        ));
    };
    validate_external_ip_literal(host)
        .map_err(|err| error_response(StatusCode::BAD_GATEWAY, &err))?;

    Ok(ResolvedHttpExternalTarget::Http(join_url(&base, uri)))
}

fn resolve_tcp_target(target: &ExternalTarget) -> Result<(String, u16), RouterError> {
    let url = configured_external_url(target, target.url_override.as_deref())
        .ok_or_else(|| RouterError::InvalidConfig(external_slot_not_configured_message(target)))?;

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
    validate_external_ip_literal(host).map_err(RouterError::InvalidConfig)?;

    Ok((host.to_string(), port))
}

fn validate_external_ip_literal(host: &str) -> Result<(), String> {
    let Ok(ip) = host.parse::<IpAddr>() else {
        return Ok(());
    };
    if is_disallowed_external_ip(ip) {
        return Err(format!(
            "external target {host} resolves to a disallowed address: {ip}"
        ));
    }
    Ok(())
}

async fn validate_external_host(host: &str, port: u16) -> Result<(), String> {
    validate_external_ip_literal(host)?;
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }

    let mut saw_addr = false;
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|err| format!("failed to resolve external target {host}:{port}: {err}"))?;
    for addr in addrs {
        saw_addr = true;
        let ip = addr.ip();
        if is_disallowed_external_ip(ip) {
            return Err(format!(
                "external target {host}:{port} resolves to a disallowed address: {ip}"
            ));
        }
    }
    if !saw_addr {
        return Err(format!(
            "external target {host}:{port} did not resolve to an address"
        ));
    }
    Ok(())
}

fn is_disallowed_external_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unicast_link_local() {
                return true;
            }
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.is_loopback() || v4.is_link_local();
            }
            false
        }
    }
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

fn configured_external_url(target: &ExternalTarget, override_url: Option<&str>) -> Option<String> {
    override_url
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            env::var(&target.url_env).ok().and_then(|value| {
                let trimmed = value.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            })
        })
}

fn external_slot_not_configured_message(target: &ExternalTarget) -> String {
    if target.optional {
        format!(
            "external slot {} is optional and not configured",
            target.name
        )
    } else {
        format!("external slot {} is not configured", target.name)
    }
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
            capability_kind: None,
            capability_profile: None,
            protocol,
            http_plugins: Vec::new(),
            target,
            allowed_issuers: allowed_issuers.iter().map(ToString::to_string).collect(),
        }
    }

    fn test_http_exchange_labels() -> HttpExchangeLabels {
        HttpExchangeLabels {
            kind: HttpEdgeKind::ExternalSlot,
            emit_telemetry: true,
            slot: Some(Arc::<str>::from("matrix")),
            capability: Arc::<str>::from("matrix"),
            capability_kind: Some(Arc::<str>::from("http")),
            capability_profile: None,
            source_component: Some(Arc::<str>::from("/bot")),
            source_endpoint: Arc::<str>::from("matrix"),
            destination_component: None,
            destination_endpoint: Arc::<str>::from("matrix"),
        }
    }

    fn empty_box_body() -> BoxBody {
        Full::new(Bytes::new())
            .map_err(|never| match never {})
            .boxed()
    }

    async fn response_text(response: Response<Incoming>) -> String {
        String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .expect("response body should collect")
                .to_bytes()
                .to_vec(),
        )
        .expect("response body should be utf-8")
    }

    async fn spawn_test_mesh_http_server(
        router_identity: &MeshIdentity,
        connection_count: Arc<std::sync::atomic::AtomicUsize>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let peer_identity = MeshIdentity::generate("proxy", Some("test-scope".to_string()));
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("mesh server should bind");
        let addr = listener
            .local_addr()
            .expect("listener should have local addr");
        let server_config = MeshConfig {
            identity: peer_identity.clone(),
            peers: vec![MeshPeer {
                id: router_identity.id.clone(),
                public_key: router_identity.public_key,
            }],
            ..test_mesh_config()
        };
        let trust = Arc::new(TrustBundle::new(&server_config).expect("mesh server trust"));
        let noise_keys = noise_keys_for_identity(&server_config.identity).expect("noise keys");

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("mesh peer should accept");
            connection_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

            let mut session = accept_noise(stream, &noise_keys, trust.as_ref())
                .await
                .expect("mesh peer should accept noise");
            let open = session.recv_open().await.expect("open frame");
            assert_eq!(open.capability, "matrix");

            let (local, remote) = duplex(64 * 1024);
            let bridge =
                tokio::spawn(async move { proxy_noise_to_plain(&mut session, local).await });
            let service = service_fn(|req: Request<Incoming>| async move {
                assert_eq!(req.uri().path(), "/_matrix/client/v3/sync");
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(
                            Full::new(Bytes::from_static(b"mesh ok"))
                                .map_err(|never| match never {})
                                .boxed(),
                        )
                        .expect("mesh response should build"),
                )
            });
            http1::Builder::new()
                .serve_connection(TokioIo::new(remote), service)
                .await
                .expect("mesh http server should complete");
            bridge
                .await
                .expect("mesh bridge task should complete")
                .expect("mesh bridge should succeed");
        });

        let peer_key = base64::engine::general_purpose::STANDARD.encode(peer_identity.public_key);
        let mut mesh_url = Url::parse(&format!("mesh://127.0.0.1:{}", addr.port()))
            .expect("mesh url should parse");
        mesh_url
            .query_pairs_mut()
            .append_pair("peer_id", &peer_identity.id)
            .append_pair("peer_key", &peer_key);
        (mesh_url.to_string(), server_task)
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
                capability_kind: None,
                capability_profile: None,
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
                capability_kind: None,
                capability_profile: None,
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
                capability_kind: None,
                capability_profile: None,
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
            capability_kind: None,
            capability_profile: None,
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
            slot: None,
            capability_kind: None,
            capability_profile: None,
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
            slot: None,
            capability_kind: None,
            capability_profile: None,
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
            slot: None,
            capability_kind: None,
            capability_profile: None,
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

    #[test]
    fn extract_json_rpc_from_text_extracts_method_and_id() {
        let rpc = extract_json_rpc_from_text(r#"{"jsonrpc":"2.0","id":7,"method":"tools/list"}"#);
        assert_eq!(rpc.method.as_deref(), Some("tools/list"));
        assert_eq!(rpc.id.as_deref(), Some("7"));
        assert_eq!(rpc.is_notification, Some(false));
        assert_eq!(rpc.error_code, None);
    }

    #[test]
    fn extract_json_rpc_from_text_extracts_batch_first_rpc_entry() {
        let rpc = extract_json_rpc_from_text(
            r#"[{"jsonrpc":"2.0","id":"a","method":"foo"},{"jsonrpc":"2.0","id":"b","method":"bar"}]"#,
        );
        assert_eq!(rpc.method.as_deref(), Some("foo"));
        assert_eq!(rpc.id.as_deref(), Some("a"));
    }

    #[test]
    fn parse_sse_events_parses_framed_messages() {
        let events = parse_sse_events(
            "id: 1\nevent: message\ndata: \
             {\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}\n\n:comment\ndata: plain\n\n",
        );
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id.as_deref(), Some("1"));
        assert_eq!(events[0].event.as_deref(), Some("message"));
        assert_eq!(
            events[0].data,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#
        );
        assert_eq!(events[1].event, None);
        assert_eq!(events[1].id, None);
        assert_eq!(events[1].data, "plain");
    }

    #[test]
    fn inbound_labels_fall_back_to_open_frame_metadata() {
        let route = InboundRoute {
            route_id: "route".to_string(),
            capability: "cap".to_string(),
            capability_kind: None,
            capability_profile: None,
            protocol: MeshProtocol::Http,
            http_plugins: Vec::new(),
            target: InboundTarget::Local { port: 7000 },
            allowed_issuers: vec!["peer".to_string()],
        };
        let open = OpenFrame {
            route_id: "route".to_string(),
            capability: "cap".to_string(),
            protocol: MeshProtocol::Http,
            slot: Some("slot".to_string()),
            capability_kind: Some("mcp".to_string()),
            capability_profile: Some("v1".to_string()),
        };

        let labels = HttpExchangeLabels::inbound_from_route(
            Arc::<str>::from("/provider"),
            Arc::<str>::from("/consumer"),
            &route,
            &open,
        );
        assert_eq!(labels.slot.as_deref(), Some("slot"));
        assert_eq!(labels.capability_kind.as_deref(), Some("mcp"));
        assert_eq!(labels.capability_profile.as_deref(), Some("v1"));
    }

    #[test]
    fn inbound_export_delivery_to_provider_is_not_observed_twice() {
        let route = InboundRoute {
            route_id: "component:/server:api:http".to_string(),
            capability: "api".to_string(),
            capability_kind: Some("mcp".to_string()),
            capability_profile: Some("debug-jsonrpc".to_string()),
            protocol: MeshProtocol::Http,
            http_plugins: Vec::new(),
            target: InboundTarget::Local { port: 9000 },
            allowed_issuers: vec!["/router".to_string()],
        };
        let open = OpenFrame {
            route_id: "router:export:public:http".to_string(),
            capability: "public".to_string(),
            protocol: MeshProtocol::Http,
            slot: Some("public".to_string()),
            capability_kind: Some("mcp".to_string()),
            capability_profile: Some("debug-jsonrpc".to_string()),
        };

        let labels = HttpExchangeLabels::inbound_from_route(
            Arc::<str>::from("/server"),
            Arc::<str>::from("/router"),
            &route,
            &open,
        );

        assert_eq!(labels.kind, HttpEdgeKind::Export);
        assert!(!labels.emit_telemetry);
        assert_eq!(labels.source_endpoint.as_ref(), "public");
        assert_eq!(labels.destination_component.as_deref(), Some("/server"));
    }

    #[test]
    fn inbound_export_labels_treat_router_slot_only_metadata_as_export() {
        let route = InboundRoute {
            route_id: "component:/server:api:http".to_string(),
            capability: "api".to_string(),
            capability_kind: Some("mcp".to_string()),
            capability_profile: Some("debug-jsonrpc".to_string()),
            protocol: MeshProtocol::Http,
            http_plugins: Vec::new(),
            target: InboundTarget::Local { port: 9000 },
            allowed_issuers: vec!["/router".to_string()],
        };
        let open = OpenFrame {
            route_id: "router:export:public:http".to_string(),
            capability: "public".to_string(),
            protocol: MeshProtocol::Http,
            slot: Some("public".to_string()),
            capability_kind: Some("mcp".to_string()),
            capability_profile: Some("debug-jsonrpc".to_string()),
        };

        let labels = HttpExchangeLabels::inbound_from_route(
            Arc::<str>::from("/server"),
            Arc::<str>::from("/router"),
            &route,
            &open,
        );

        assert_eq!(labels.kind, HttpEdgeKind::Export);
        assert!(!labels.emit_telemetry);
        assert_eq!(labels.source_endpoint.as_ref(), "public");
        assert_eq!(labels.destination_component.as_deref(), Some("/server"));
    }

    #[test]
    fn external_slot_destination_ref_is_user_facing() {
        let route = OutboundRoute {
            route_id: "router:external:ext_api:http".to_string(),
            slot: "ext_api".to_string(),
            capability_kind: Some("http".to_string()),
            capability_profile: Some("debug-external".to_string()),
            listen_port: 20000,
            listen_addr: None,
            protocol: MeshProtocol::Http,
            peer_addr: "router:24000".to_string(),
            peer_id: "/router".to_string(),
            capability: "ext_api".to_string(),
            http_plugins: Vec::new(),
        };

        let labels = HttpExchangeLabels::outbound_from_route(Arc::<str>::from("/client"), &route);
        assert_eq!(destination_ref_for(&labels), "external.ext_api");
        assert_eq!(
            edge_ref_for(
                RewriteFlow::Outbound,
                &labels,
                "/client.ext_api",
                "external.ext_api"
            ),
            "/client.ext_api -> external.ext_api"
        );
    }

    #[test]
    fn export_messages_use_user_facing_component_story() {
        let route = InboundRoute {
            route_id: "router:export:public:http".to_string(),
            capability: "public".to_string(),
            capability_kind: Some("mcp".to_string()),
            capability_profile: Some("debug-jsonrpc".to_string()),
            protocol: MeshProtocol::Http,
            http_plugins: Vec::new(),
            target: InboundTarget::MeshForward {
                peer_addr: "server:23000".to_string(),
                peer_id: "/server".to_string(),
                route_id: "component:/server:api:http".to_string(),
                capability: "api".to_string(),
            },
            allowed_issuers: vec!["/router".to_string()],
        };
        let open = OpenFrame {
            route_id: "router:export:public:http".to_string(),
            capability: "public".to_string(),
            protocol: MeshProtocol::Http,
            slot: Some("public".to_string()),
            capability_kind: Some("mcp".to_string()),
            capability_profile: Some("debug-jsonrpc".to_string()),
        };
        let labels = HttpExchangeLabels::inbound_from_route(
            Arc::<str>::from("/router"),
            Arc::<str>::from("/proxy/example"),
            &route,
            &open,
        );
        let telemetry = HttpExchangeTelemetryContext::new(RewriteFlow::Inbound, &labels);

        assert_eq!(
            exchange_message(
                &telemetry,
                HttpLifecyclePart::Request,
                &ProtocolSummary::default(),
            ),
            "request received from public by /server"
        );
    }

    #[test]
    fn rewrite_flow_maps_to_expected_otel_kind() {
        assert_eq!(RewriteFlow::Inbound.otel_kind(), "server");
        assert_eq!(RewriteFlow::Outbound.otel_kind(), "client");
    }

    #[test]
    fn otel_status_code_for_http_marks_server_errors() {
        assert_eq!(otel_status_code_for_http(StatusCode::OK), "ok");
        assert_eq!(otel_status_code_for_http(StatusCode::NOT_FOUND), "ok");
        assert_eq!(
            otel_status_code_for_http(StatusCode::INTERNAL_SERVER_ERROR),
            "error"
        );
    }

    #[test]
    fn resolve_http_external_target_with_override_returns_service_unavailable_when_missing() {
        let target = ExternalTarget {
            name: "matrix".to_string(),
            url_env: "MATRIX_URL".to_string(),
            optional: false,
            url_override: None,
        };

        let response = resolve_http_external_target_with_override(
            &target,
            None,
            &Uri::from_static("/_matrix/client/v3/sync"),
        )
        .expect_err("missing external slot should fail");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn resolve_http_external_target_with_override_joins_http_targets_per_request() {
        let target = ExternalTarget {
            name: "matrix".to_string(),
            url_env: "MATRIX_URL".to_string(),
            optional: false,
            url_override: None,
        };

        let resolved = resolve_http_external_target_with_override(
            &target,
            Some("http://8.8.8.8:6167/base"),
            &Uri::from_static("/_matrix/client/v3/sync?timeout=30000"),
        )
        .expect("http target should resolve");

        let ResolvedHttpExternalTarget::Http(url) = resolved else {
            panic!("expected direct http target");
        };
        assert_eq!(
            url.as_str(),
            "http://8.8.8.8:6167/base/_matrix/client/v3/sync?timeout=30000"
        );
    }

    #[test]
    fn resolve_http_external_target_with_override_rejects_loopback_ip_literals() {
        let target = ExternalTarget {
            name: "matrix".to_string(),
            url_env: "MATRIX_URL".to_string(),
            optional: false,
            url_override: None,
        };

        let response = resolve_http_external_target_with_override(
            &target,
            Some("http://127.0.0.1:6167/base"),
            &Uri::from_static("/_matrix/client/v3/sync"),
        )
        .expect_err("loopback target should be rejected");

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn resolve_http_external_target_with_override_accepts_private_ip_literals() {
        let target = ExternalTarget {
            name: "matrix".to_string(),
            url_env: "MATRIX_URL".to_string(),
            optional: false,
            url_override: None,
        };

        let resolved = resolve_http_external_target_with_override(
            &target,
            Some("http://10.0.0.8:6167/base"),
            &Uri::from_static("/_matrix/client/v3/sync"),
        )
        .expect("private target should resolve");

        let ResolvedHttpExternalTarget::Http(url) = resolved else {
            panic!("expected direct http target");
        };
        assert_eq!(
            url.as_str(),
            "http://10.0.0.8:6167/base/_matrix/client/v3/sync"
        );
    }

    #[test]
    fn resolve_http_external_target_with_override_preserves_mesh_targets() {
        let peer_key = base64::engine::general_purpose::STANDARD.encode([251u8; 32]);
        assert!(
            peer_key.contains('+'),
            "regression test requires a base64 peer key with '+'"
        );
        let mut mesh_url =
            Url::parse("mesh://host.docker.internal:61662").expect("mesh url should parse");
        mesh_url
            .query_pairs_mut()
            .append_pair("peer_id", "/proxy")
            .append_pair("peer_key", &peer_key);
        let mesh_url = mesh_url.to_string();
        let target = ExternalTarget {
            name: "matrix".to_string(),
            url_env: "MATRIX_URL".to_string(),
            optional: false,
            url_override: None,
        };

        let resolved = resolve_http_external_target_with_override(
            &target,
            Some(mesh_url.as_str()),
            &Uri::from_static("/_matrix/client/v3/sync"),
        )
        .expect("mesh target should resolve");

        let ResolvedHttpExternalTarget::Mesh { target_url, mesh } = resolved else {
            panic!("expected mesh target");
        };
        assert_eq!(target_url, mesh_url);
        assert_eq!(mesh.peer_addr, "host.docker.internal:61662");
        assert_eq!(mesh.peer_id, "/proxy");
    }

    #[tokio::test]
    async fn resolve_http_external_target_reads_live_overrides() {
        let external_overrides: ExternalOverrides = Arc::new(RwLock::new(HashMap::new()));
        let state = HttpProxyState {
            client: build_client(),
            target: ExternalTarget {
                name: "matrix".to_string(),
                url_env: "MATRIX_URL".to_string(),
                optional: false,
                url_override: None,
            },
            labels: test_http_exchange_labels(),
            config: Arc::new(test_mesh_config()),
            external_overrides: external_overrides.clone(),
            mesh_upstream: Arc::new(Mutex::new(None)),
        };
        let uri = Uri::from_static("/_matrix/client/v3/sync");

        let first = resolve_http_external_target(&state, &uri)
            .await
            .expect_err("unconfigured external slot should fail");
        assert_eq!(first.status(), StatusCode::SERVICE_UNAVAILABLE);

        external_overrides
            .write()
            .await
            .insert("matrix".to_string(), "http://8.8.8.8:6167".to_string());

        let second = resolve_http_external_target(&state, &uri)
            .await
            .expect("new override should be visible");
        let ResolvedHttpExternalTarget::Http(url) = second else {
            panic!("expected direct http target after override registration");
        };
        assert_eq!(url.as_str(), "http://8.8.8.8:6167/_matrix/client/v3/sync");
    }

    #[tokio::test]
    async fn resolve_http_external_target_rejects_localhost_overrides() {
        let external_overrides: ExternalOverrides = Arc::new(RwLock::new(HashMap::new()));
        let state = HttpProxyState {
            client: build_client(),
            target: ExternalTarget {
                name: "matrix".to_string(),
                url_env: "MATRIX_URL".to_string(),
                optional: false,
                url_override: None,
            },
            labels: test_http_exchange_labels(),
            config: Arc::new(test_mesh_config()),
            external_overrides: external_overrides.clone(),
            mesh_upstream: Arc::new(Mutex::new(None)),
        };
        let uri = Uri::from_static("/_matrix/client/v3/sync");

        external_overrides
            .write()
            .await
            .insert("matrix".to_string(), "http://localhost:6167".to_string());

        let response = resolve_http_external_target(&state, &uri)
            .await
            .expect_err("localhost override should be rejected");

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn resolve_tcp_target_rejects_loopback_ip_literals() {
        let target = ExternalTarget {
            name: "matrix".to_string(),
            url_env: "MATRIX_URL".to_string(),
            optional: false,
            url_override: Some("tcp://127.0.0.1:6167".to_string()),
        };

        let err = resolve_tcp_target(&target).expect_err("loopback target should be rejected");
        assert!(
            err.to_string().contains("disallowed address"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_tcp_target_accepts_private_ip_literals() {
        let target = ExternalTarget {
            name: "matrix".to_string(),
            url_env: "MATRIX_URL".to_string(),
            optional: false,
            url_override: Some("tcp://10.0.0.8:6167".to_string()),
        };

        let resolved = resolve_tcp_target(&target).expect("private target should resolve");
        assert_eq!(resolved, ("10.0.0.8".to_string(), 6167));
    }

    #[tokio::test]
    async fn late_mesh_slot_registration_succeeds_on_same_http_connection() {
        let config = Arc::new(test_mesh_config());
        let external_overrides: ExternalOverrides = Arc::new(RwLock::new(HashMap::new()));
        let connection_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (mesh_url, mesh_server_task) =
            spawn_test_mesh_http_server(&config.identity, connection_count.clone()).await;
        let state = HttpProxyState {
            client: build_client(),
            target: ExternalTarget {
                name: "matrix".to_string(),
                url_env: "MATRIX_URL".to_string(),
                optional: false,
                url_override: None,
            },
            labels: test_http_exchange_labels(),
            config: config.clone(),
            external_overrides: external_overrides.clone(),
            mesh_upstream: Arc::new(Mutex::new(None)),
        };
        let (client_side, server_side) = duplex(64 * 1024);
        let proxy_state = state.clone();
        let proxy_task = tokio::spawn(async move {
            let service = service_fn(move |req: Request<Incoming>| {
                let state = proxy_state.clone();
                async move { Ok::<_, std::convert::Infallible>(proxy_http_request(state, req).await) }
            });
            http1::Builder::new()
                .serve_connection(TokioIo::new(server_side), service)
                .await
                .expect("proxy http server should complete");
        });
        let (mut sender, conn) = client_http1::handshake(TokioIo::new(client_side))
            .await
            .expect("client handshake should succeed");
        let client_task = tokio::spawn(async move {
            conn.await.expect("client connection should complete");
        });

        let first = sender
            .send_request(
                Request::builder()
                    .uri("/_matrix/client/v3/sync")
                    .header(header::HOST, "tuwunel.test")
                    .body(empty_box_body())
                    .expect("first request should build"),
            )
            .await
            .expect("first response should arrive");
        assert_eq!(first.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response_text(first).await,
            "external slot matrix is not configured"
        );

        external_overrides
            .write()
            .await
            .insert("matrix".to_string(), mesh_url);

        let second = sender
            .send_request(
                Request::builder()
                    .uri("/_matrix/client/v3/sync")
                    .header(header::HOST, "tuwunel.test")
                    .body(empty_box_body())
                    .expect("second request should build"),
            )
            .await
            .expect("second response should arrive");
        let second_status = second.status();
        let second_body = response_text(second).await;
        assert_eq!(
            second_status,
            StatusCode::OK,
            "second response body: {second_body}"
        );
        assert_eq!(second_body, "mesh ok");

        let third = sender
            .send_request(
                Request::builder()
                    .uri("/_matrix/client/v3/sync")
                    .header(header::HOST, "tuwunel.test")
                    .body(empty_box_body())
                    .expect("third request should build"),
            )
            .await
            .expect("third response should arrive");
        let third_status = third.status();
        let third_body = response_text(third).await;
        assert_eq!(
            third_status,
            StatusCode::OK,
            "third response body: {third_body}"
        );
        assert_eq!(third_body, "mesh ok");
        assert_eq!(
            connection_count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "mesh upstream should be reused once registered"
        );

        drop(sender);
        drop(state);
        let _ = client_task.await;
        let _ = proxy_task.await;
        let _ = mesh_server_task.await;
    }
}
