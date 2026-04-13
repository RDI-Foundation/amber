use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    env,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    path::Path,
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
    task::{Context, Poll},
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
    client::legacy::{
        Client,
        connect::{
            HttpConnector,
            dns::{GaiResolver, Name},
        },
    },
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
use tower::{Service, ServiceBuilder, ServiceExt as _, service_fn as tower_service_fn};
use tower_http::{compression::CompressionLayer, decompression::Decompression};
use tracing::Instrument as _;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use url::Url;

mod a2a;
pub mod control;
mod dynamic_caps;
mod external;
mod http_forward;
mod http_observability;
#[cfg(test)]
mod tests;
mod transport;

use self::{
    control::*, dynamic_caps::*, external::*, http_forward::*, http_observability::*, transport::*,
};

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
    vetted_external_addrs: VettedExternalAddrs,
    mesh_upstream: Arc<Mutex<Option<MeshHttpUpstream>>>,
    route_id: Option<Arc<str>>,
    peer_id: Option<Arc<str>>,
}

#[derive(Clone)]
struct LocalHttpProxyState {
    client: HttpClient,
    base_url: Url,
    plugins: Arc<[Arc<dyn HttpExchangePlugin>]>,
    route_id: Arc<str>,
    peer_id: Arc<str>,
    labels: HttpExchangeLabels,
    dynamic_caps: Option<Arc<DynamicCapsRuntime>>,
}

const AMBER_ROUTE_ID_HEADER: &str = "x-amber-route-id";
const AMBER_PEER_ID_HEADER: &str = "x-amber-peer-id";
const AMBER_FRAMEWORK_AUTH_HEADER: &str = "x-amber-framework-auth";

fn framework_component_auth_header_value() -> Option<HeaderValue> {
    env::var(amber_mesh::FRAMEWORK_COMPONENT_CONTROLLER_AUTH_TOKEN_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .and_then(|value| HeaderValue::from_str(&value).ok())
}

#[derive(Clone)]
struct OutboundHttpProxyState {
    upstream: Arc<Mutex<client_http1::SendRequest<BoxBody>>>,
    plugins: Arc<[Arc<dyn HttpExchangePlugin>]>,
    route_id: Arc<str>,
    peer_id: Arc<str>,
    labels: HttpExchangeLabels,
    dynamic_caps: Option<Arc<DynamicCapsRuntime>>,
}

type HttpClient = Client<HttpsConnector<HttpConnector<ExternalHttpResolver>>, BoxBody>;

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
    http_subject: Option<Arc<str>>,
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
    fn new(flow: RewriteFlow, labels: &HttpExchangeLabels, http_subject: Option<String>) -> Self {
        let source_ref = Arc::<str>::from(source_ref_for(labels).into_boxed_str());
        let destination_ref = Arc::<str>::from(destination_ref_for(labels).into_boxed_str());
        let edge_ref = Arc::<str>::from(
            edge_ref_for(flow, labels, &source_ref, &destination_ref).into_boxed_str(),
        );
        Self {
            flow,
            http_subject: http_subject.map(Arc::<str>::from),
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

    fn http_subject(&self) -> Option<&str> {
        self.http_subject.as_deref()
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
    route_id: Option<String>,
    capability: Option<String>,
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
type VettedExternalAddrs = Arc<RwLock<HashMap<String, Vec<SocketAddr>>>>;
type ControlAllowlist = Arc<HashSet<IpAddr>>;
type DynamicIssuers = Arc<RwLock<HashMap<String, HashSet<String>>>>;
type InboundRoutes = HashMap<String, InboundRoute>;
type DynamicRouteOverlays = Arc<RwLock<HashMap<String, DynamicRouteOverlay>>>;

#[derive(Clone, Debug)]
struct DynamicRouteOverlay {
    routes: HashMap<String, InboundRoute>,
    peers: Vec<MeshPeer>,
    static_issuer_grants: HashMap<String, HashSet<String>>,
}

type ExternalHttpResolveFuture =
    Pin<Box<dyn Future<Output = io::Result<std::vec::IntoIter<SocketAddr>>> + Send>>;

#[derive(Clone)]
struct ExternalHttpResolver {
    vetted_external_addrs: VettedExternalAddrs,
    fallback: GaiResolver,
}

impl Service<Name> for ExternalHttpResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = io::Error;
    type Future = ExternalHttpResolveFuture;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.fallback.poll_ready(cx)
    }

    fn call(&mut self, name: Name) -> Self::Future {
        let host = name.as_str().to_string();
        let vetted_external_addrs = self.vetted_external_addrs.clone();
        let mut fallback = self.fallback.clone();

        Box::pin(async move {
            if let Some(addrs) = vetted_external_addrs.read().await.get(&host).cloned() {
                return Ok(addrs.into_iter());
            }

            Ok(fallback.call(name).await?.collect::<Vec<_>>().into_iter())
        })
    }
}

async fn proxy_local_http_request(
    state: LocalHttpProxyState,
    req: Request<Incoming>,
) -> Response<BoxBody> {
    let emit_telemetry = state.labels.emit_telemetry;
    let request_is_agent_card = a2a::is_agent_card_path(req.uri().path());
    let telemetry = HttpExchangeTelemetryContext::new(
        RewriteFlow::Inbound,
        &state.labels,
        http_subject_from_path(req.uri().path()),
    );
    let span = if emit_telemetry {
        start_http_exchange_span(&telemetry, &req)
    } else {
        tracing::Span::none()
    };
    let instrument_span = span.clone();
    let status_span = span.clone();
    let status_telemetry = telemetry.clone();

    let response = async move {
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
        let auto_materialize_request = state.dynamic_caps.is_some()
            && state.labels.capability_kind.as_deref() == Some("a2a")
            && a2a::is_json_content_type(
                parts
                    .0
                    .headers
                    .get(header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
            );
        let request_body_collect = auto_materialize_request
            || matching_plugins
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
            if let Some(dynamic_caps) = state.dynamic_caps.as_ref()
                && auto_materialize_request
            {
                match dynamic_caps
                    .rewrite_dynamic_refs_in_a2a_body(&mut body)
                    .await
                {
                    Ok(dynamic_rewritten) => {
                        rewritten |= dynamic_rewritten;
                    }
                    Err(err) => {
                        tracing::warn!(
                            target: "amber.internal",
                            code = ?err.code,
                            message = %err.message,
                            "dynamic capability auto-materialization failed on inbound request"
                        );
                        return protocol_response(&err);
                    }
                }
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
        request_parts.headers.insert(
            header::HeaderName::from_static(AMBER_ROUTE_ID_HEADER),
            HeaderValue::from_str(state.route_id.as_ref())
                .expect("route id header value should be valid"),
        );
        request_parts.headers.insert(
            header::HeaderName::from_static(AMBER_PEER_ID_HEADER),
            HeaderValue::from_str(state.peer_id.as_ref())
                .expect("peer id header value should be valid"),
        );
        if let Some(auth_token) = framework_component_auth_header_value() {
            request_parts.headers.insert(
                header::HeaderName::from_static(AMBER_FRAMEWORK_AUTH_HEADER),
                auth_token,
            );
        }
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
    peer_id: Arc<str>,
    stream: tokio::net::TcpStream,
    plugins: Arc<[Arc<dyn HttpExchangePlugin>]>,
    labels: HttpExchangeLabels,
    dynamic_caps: Option<Arc<DynamicCapsRuntime>>,
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
        peer_id,
        labels,
        dynamic_caps,
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
    let request_is_agent_card = a2a::is_agent_card_path(req.uri().path());
    let telemetry = HttpExchangeTelemetryContext::new(
        flow,
        &state.labels,
        http_subject_from_path(req.uri().path()),
    );
    let span = start_http_exchange_span(&telemetry, &req);
    let instrument_span = span.clone();
    let status_span = span.clone();
    let status_telemetry = telemetry.clone();

    let response = async move {
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
        let auto_materialize_response = state.dynamic_caps.is_some()
            && flow == RewriteFlow::Outbound
            && state.labels.capability_kind.as_deref() == Some("a2a");
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
        if response_body_collect || auto_materialize_response || !matching_plugins.is_empty() {
            request_parts.headers.remove(header::ACCEPT_ENCODING);
        }
        let host_header = outgoing_host_header(&request_parts.uri, &request_parts.headers);
        sanitize_request_headers(&mut request_parts.headers, host_header.as_str());
        request_parts.headers.insert(
            header::HeaderName::from_static(AMBER_ROUTE_ID_HEADER),
            HeaderValue::from_str(state.route_id.as_ref())
                .expect("route id header value should be valid"),
        );
        request_parts.headers.insert(
            header::HeaderName::from_static(AMBER_PEER_ID_HEADER),
            HeaderValue::from_str(state.peer_id.as_ref())
                .expect("peer id header value should be valid"),
        );
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

        let auto_materialize_response = auto_materialize_response
            && a2a::is_json_content_type(
                response
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
            );

        if response_body_collect || auto_materialize_response {
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
            if let Some(dynamic_caps) = state.dynamic_caps.as_ref()
                && auto_materialize_response
            {
                match dynamic_caps
                    .rewrite_dynamic_refs_in_a2a_body(&mut body)
                    .await
                {
                    Ok(dynamic_rewritten) => {
                        rewritten |= dynamic_rewritten;
                    }
                    Err(err) => {
                        tracing::warn!(
                            target: "amber.internal",
                            code = ?err.code,
                            message = %err.message,
                            "dynamic capability auto-materialization failed on outbound response"
                        );
                        return protocol_response(&err);
                    }
                }
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
    let telemetry = HttpExchangeTelemetryContext::new(
        RewriteFlow::Outbound,
        &state.labels,
        http_subject_from_path(req.uri().path()),
    );
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
                return *err;
            }
        };

        sanitize_request_headers(&mut parts.0.headers, &host_header);
        if let Some(route_id) = state.route_id.as_ref()
            && !parts
                .0
                .headers
                .contains_key(header::HeaderName::from_static(AMBER_ROUTE_ID_HEADER))
        {
            parts.0.headers.insert(
                header::HeaderName::from_static(AMBER_ROUTE_ID_HEADER),
                HeaderValue::from_str(route_id.as_ref())
                    .expect("route id header value should be valid"),
            );
        }
        if let Some(peer_id) = state.peer_id.as_ref()
            && !parts
                .0
                .headers
                .contains_key(header::HeaderName::from_static(AMBER_PEER_ID_HEADER))
        {
            parts.0.headers.insert(
                header::HeaderName::from_static(AMBER_PEER_ID_HEADER),
                HeaderValue::from_str(peer_id.as_ref())
                    .expect("peer id header value should be valid"),
            );
        }
        if let Some(auth_token) = framework_component_auth_header_value() {
            parts.0.headers.insert(
                header::HeaderName::from_static(AMBER_FRAMEWORK_AUTH_HEADER),
                auth_token,
            );
        }
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
type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;
