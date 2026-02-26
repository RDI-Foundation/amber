use std::{
    collections::{HashMap, HashSet},
    env,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use base64::Engine as _;
use bytes::Bytes;
use dashmap::DashMap;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{
    Method, Request, Response, StatusCode, Uri,
    body::Incoming,
    header,
    http::{HeaderMap, HeaderValue},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::{
    client::legacy::Client,
    rt::{TokioExecutor, TokioIo},
};
use hyperlocal::{UnixConnector, Uri as HyperlocalUri};
use serde::Deserialize;
use thiserror::Error;
use tokio::net::{TcpListener, UnixStream};
use url::form_urlencoded;

const CONFIG_B64_ENV: &str = "AMBER_DOCKER_GATEWAY_CONFIG_B64";
const CONFIG_JSON_ENV: &str = "AMBER_DOCKER_GATEWAY_CONFIG_JSON";
const COMPOSE_PROJECT_LABEL: &str = "com.docker.compose.project";
const COMPOSE_SERVICE_LABEL: &str = "com.docker.compose.service";
const COMPOSE_NETWORK_LABEL: &str = "com.docker.compose.network";
const COMPOSE_VOLUME_LABEL: &str = "com.docker.compose.volume";
const AMBER_COMPONENT_LABEL: &str = "com.rdi.amber.component";

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type ProxyBody = BoxBody<Bytes, BoxError>;
type GatewayResult<T> = Result<T, Box<Response<ProxyBody>>>;

#[derive(Debug, Error)]
pub enum DockerGatewayError {
    #[error("missing docker gateway config (set {CONFIG_B64_ENV} or {CONFIG_JSON_ENV})")]
    MissingConfig,
    #[error("invalid docker gateway config: {0}")]
    InvalidConfig(String),
    #[error("failed to bind {addr}: {source}")]
    BindFailed {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Clone, Debug, Deserialize)]
pub struct DockerGatewayConfig {
    pub listen: SocketAddr,
    pub docker_sock: PathBuf,
    pub compose_project: String,
    pub callers: Vec<CallerConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CallerConfig {
    pub ip: IpAddr,
    #[serde(default)]
    pub port: Option<u16>,
    pub component: String,
}

#[derive(Clone)]
struct ConnState {
    state: Arc<State>,
    peer: SocketAddr,
    identity: Option<CallerIdentity>,
}

struct State {
    cfg: Arc<DockerGatewayConfig>,
    client: Client<UnixConnector, ProxyBody>,
    exec_map: DashMap<String, String>,
}

#[derive(Clone, Debug)]
struct OwnerMeta {
    component: Option<String>,
    compose_project: Option<String>,
}

#[derive(Clone, Debug)]
struct CallerIdentity {
    component: String,
}

#[derive(Debug, Deserialize)]
struct ContainerInspectResponse {
    #[serde(rename = "Config")]
    config: Option<ContainerInspectConfig>,
}

#[derive(Debug, Deserialize)]
struct ContainerInspectConfig {
    #[serde(rename = "Labels")]
    labels: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct NetworkInspectResponse {
    #[serde(rename = "Labels")]
    labels: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct VolumeInspectResponse {
    #[serde(rename = "Labels")]
    labels: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct ExecInspectResponse {
    #[serde(rename = "ContainerID")]
    container_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ContainerCreateRequest {
    #[serde(default)]
    host_config: Option<HostConfigRequest>,
    #[serde(default)]
    networking_config: Option<NetworkingConfigRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct HostConfigRequest {
    #[serde(default)]
    network_mode: Option<String>,
    #[serde(default)]
    binds: Vec<String>,
    #[serde(default)]
    mounts: Vec<MountRequest>,
    #[serde(default)]
    volumes_from: Vec<String>,
    #[serde(default)]
    links: Vec<String>,
    #[serde(default)]
    pid_mode: Option<String>,
    #[serde(default)]
    ipc_mode: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct MountRequest {
    #[serde(default, rename = "Type")]
    mount_type: Option<String>,
    #[serde(default)]
    source: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct NetworkingConfigRequest {
    #[serde(default)]
    endpoints_config: HashMap<String, serde_json::Value>,
}

impl DockerGatewayConfig {
    pub fn from_env() -> Result<Self, DockerGatewayError> {
        if let Ok(b64) = env::var(CONFIG_B64_ENV) {
            if b64.trim().is_empty() {
                return Err(DockerGatewayError::MissingConfig);
            }
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(b64.as_bytes())
                .map_err(|err| DockerGatewayError::InvalidConfig(err.to_string()))?;
            let parsed = serde_json::from_slice(&decoded)
                .map_err(|err| DockerGatewayError::InvalidConfig(err.to_string()))?;
            return Self::validate(parsed);
        }

        if let Ok(raw) = env::var(CONFIG_JSON_ENV) {
            if raw.trim().is_empty() {
                return Err(DockerGatewayError::MissingConfig);
            }
            let parsed = serde_json::from_str(&raw)
                .map_err(|err| DockerGatewayError::InvalidConfig(err.to_string()))?;
            return Self::validate(parsed);
        }

        Err(DockerGatewayError::MissingConfig)
    }

    fn validate(config: Self) -> Result<Self, DockerGatewayError> {
        if config.compose_project.trim().is_empty() {
            return Err(DockerGatewayError::InvalidConfig(
                "compose_project must not be empty".to_string(),
            ));
        }
        if config.callers.is_empty() {
            return Err(DockerGatewayError::InvalidConfig(
                "callers must not be empty".to_string(),
            ));
        }
        Ok(config)
    }
}

impl CallerConfig {
    fn matches(&self, addr: SocketAddr) -> bool {
        if self.ip != addr.ip() {
            return false;
        }
        match self.port {
            Some(port) => port == addr.port(),
            None => true,
        }
    }
}

impl State {
    fn new(config: DockerGatewayConfig) -> Self {
        let connector = UnixConnector;
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Self {
            cfg: Arc::new(config),
            client,
            exec_map: DashMap::new(),
        }
    }

    fn resolve_identity(&self, peer: SocketAddr) -> Option<CallerIdentity> {
        self.cfg
            .callers
            .iter()
            .find(|entry| entry.matches(peer))
            .map(|entry| CallerIdentity {
                component: entry.component.clone(),
            })
    }
}

pub async fn run(config: DockerGatewayConfig) -> Result<(), DockerGatewayError> {
    let state = Arc::new(State::new(config));

    let listener = TcpListener::bind(state.cfg.listen)
        .await
        .map_err(|source| DockerGatewayError::BindFailed {
            addr: state.cfg.listen,
            source,
        })?;

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(value) => value,
            Err(err) => {
                eprintln!("docker gateway accept failed: {err}");
                continue;
            }
        };

        let conn_state = Arc::new(ConnState {
            state: state.clone(),
            peer,
            identity: state.resolve_identity(peer),
        });

        let io = TokioIo::new(stream);
        let svc = service_fn(move |req: Request<Incoming>| {
            let conn_state = conn_state.clone();
            async move {
                let req = req.map(box_body_from_incoming);
                Ok::<_, std::convert::Infallible>(handle(req, conn_state).await)
            }
        });

        tokio::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(io, svc)
                .with_upgrades()
                .await
            {
                eprintln!("docker gateway connection failed: {err}");
            }
        });
    }
}

async fn handle(mut req: Request<ProxyBody>, conn: Arc<ConnState>) -> Response<ProxyBody> {
    let id = match conn.identity.clone() {
        Some(identity) => identity,
        None => {
            return docker_error(
                StatusCode::UNAUTHORIZED,
                format!("unauthorized peer {}", conn.peer),
            );
        }
    };

    let (ver_opt, segs) = split_version_and_segments(req.uri().path());
    let version_prefix = ver_opt.unwrap_or_else(|| "".to_string());

    if is_ping(&segs, req.method()) || is_version(&segs, req.method()) {
        return forward(req, conn.state.clone()).await;
    }

    if req.method() == Method::GET
        && segs.len() == 2
        && segs[0] == "containers"
        && segs[1] == "json"
    {
        let required = required_label_filters(&conn.state, &id);
        match add_label_filters_to_uri(req.uri(), &required) {
            Ok(new_uri) => *req.uri_mut() = new_uri,
            Err(resp) => return *resp,
        }
        return forward(req, conn.state.clone()).await;
    }

    if req.method() == Method::GET && segs.len() == 1 && segs[0] == "events" {
        let required = required_label_filters(&conn.state, &id);
        match add_label_filters_to_uri(req.uri(), &required) {
            Ok(new_uri) => *req.uri_mut() = new_uri,
            Err(resp) => return *resp,
        }
        return forward(req, conn.state.clone()).await;
    }

    if req.method() == Method::POST
        && segs.len() == 2
        && segs[0] == "containers"
        && segs[1] == "prune"
    {
        let required = required_label_filters(&conn.state, &id);
        match add_label_filters_to_uri(req.uri(), &required) {
            Ok(new_uri) => *req.uri_mut() = new_uri,
            Err(resp) => return *resp,
        }
        return forward(req, conn.state.clone()).await;
    }

    if req.method() == Method::GET && segs.len() == 1 && segs[0] == "networks" {
        let required = required_label_filters(&conn.state, &id);
        match add_label_filters_to_uri(req.uri(), &required) {
            Ok(new_uri) => *req.uri_mut() = new_uri,
            Err(resp) => return *resp,
        }
        return forward(req, conn.state.clone()).await;
    }

    if req.method() == Method::POST
        && segs.len() == 2
        && segs[0] == "networks"
        && segs[1] == "prune"
    {
        let required = required_label_filters(&conn.state, &id);
        match add_label_filters_to_uri(req.uri(), &required) {
            Ok(new_uri) => *req.uri_mut() = new_uri,
            Err(resp) => return *resp,
        }
        return forward(req, conn.state.clone()).await;
    }

    if req.method() == Method::GET && segs.len() == 1 && segs[0] == "volumes" {
        let required = required_label_filters(&conn.state, &id);
        match add_label_filters_to_uri(req.uri(), &required) {
            Ok(new_uri) => *req.uri_mut() = new_uri,
            Err(resp) => return *resp,
        }
        return forward(req, conn.state.clone()).await;
    }

    if req.method() == Method::POST && segs.len() == 2 && segs[0] == "volumes" && segs[1] == "prune"
    {
        let required = required_label_filters(&conn.state, &id);
        match add_label_filters_to_uri(req.uri(), &required) {
            Ok(new_uri) => *req.uri_mut() = new_uri,
            Err(resp) => return *resp,
        }
        return forward(req, conn.state.clone()).await;
    }

    if req.method() == Method::POST
        && segs.len() == 2
        && segs[0] == "containers"
        && segs[1] == "create"
    {
        let (parts, body) = req.into_parts();
        let collected = match body.collect().await {
            Ok(c) => c,
            Err(err) => {
                return docker_error(StatusCode::BAD_REQUEST, format!("read body failed: {err}"));
            }
        };
        let raw = collected.to_bytes();

        if let Err(resp) =
            authorize_container_create_references(conn.state.clone(), &version_prefix, &raw, &id)
                .await
        {
            return *resp;
        }

        let mut to_set = owner_label_pairs(&conn.state, &id);
        to_set.push((COMPOSE_SERVICE_LABEL.to_string(), id.component.clone()));

        let new_body = match inject_labels_into_create_body(raw, &to_set) {
            Ok(body) => body,
            Err(resp) => return *resp,
        };

        let mut req = Request::from_parts(parts, box_body_from_bytes(new_body.clone()));
        set_content_length(&mut req, new_body.len());
        return forward(req, conn.state.clone()).await;
    }

    if req.method() == Method::POST
        && segs.len() == 2
        && segs[0] == "networks"
        && segs[1] == "create"
    {
        let (parts, body) = req.into_parts();
        let collected = match body.collect().await {
            Ok(c) => c,
            Err(err) => {
                return docker_error(StatusCode::BAD_REQUEST, format!("read body failed: {err}"));
            }
        };
        let raw = collected.to_bytes();

        let mut to_set = owner_label_pairs(&conn.state, &id);
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&raw)
            && let Some(name) = value.get("Name").and_then(|v| v.as_str())
        {
            to_set.push((COMPOSE_NETWORK_LABEL.to_string(), name.to_string()));
        }

        let new_body = match inject_labels_into_create_body(raw, &to_set) {
            Ok(body) => body,
            Err(resp) => return *resp,
        };

        let mut req = Request::from_parts(parts, box_body_from_bytes(new_body.clone()));
        set_content_length(&mut req, new_body.len());
        return forward(req, conn.state.clone()).await;
    }

    if req.method() == Method::POST
        && segs.len() == 2
        && segs[0] == "volumes"
        && segs[1] == "create"
    {
        let (parts, body) = req.into_parts();
        let collected = match body.collect().await {
            Ok(c) => c,
            Err(err) => {
                return docker_error(StatusCode::BAD_REQUEST, format!("read body failed: {err}"));
            }
        };
        let raw = collected.to_bytes();

        let mut to_set = owner_label_pairs(&conn.state, &id);
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&raw)
            && let Some(name) = value.get("Name").and_then(|v| v.as_str())
        {
            to_set.push((COMPOSE_VOLUME_LABEL.to_string(), name.to_string()));
        }

        let new_body = match inject_labels_into_create_body(raw, &to_set) {
            Ok(body) => body,
            Err(resp) => return *resp,
        };

        let mut req = Request::from_parts(parts, box_body_from_bytes(new_body.clone()));
        set_content_length(&mut req, new_body.len());
        return forward(req, conn.state.clone()).await;
    }

    if req.method() == Method::POST
        && segs.len() == 3
        && segs[0] == "containers"
        && segs[2] == "exec"
    {
        let container = &segs[1];
        if let Err(resp) =
            authorize_container(conn.state.clone(), &version_prefix, container, &id).await
        {
            return *resp;
        }

        let mut req = req;
        if let Err(resp) = rewrite_to_docker_uri(&mut req, &conn.state.cfg.docker_sock) {
            return *resp;
        }
        ensure_host(&mut req);

        let res = match conn.state.client.request(req).await {
            Ok(resp) => resp,
            Err(err) => {
                return docker_error(
                    StatusCode::BAD_GATEWAY,
                    format!("docker upstream error: {err}"),
                );
            }
        };

        let status = res.status();
        let headers = res.headers().clone();
        let collected = match res.into_body().collect().await {
            Ok(c) => c,
            Err(err) => {
                return docker_error(
                    StatusCode::BAD_GATEWAY,
                    format!("read exec create response failed: {err}"),
                );
            }
        };
        let body = collected.to_bytes();

        if status.is_success()
            && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body)
            && let Some(exec_id) = value.get("Id").and_then(|v| v.as_str())
        {
            conn.state
                .exec_map
                .insert(exec_id.to_string(), container.to_string());
        }

        return response_from_upstream(status, headers, body);
    }

    if segs.len() >= 2 && segs[0] == "exec" {
        let exec_id = &segs[1];
        let container_id =
            match resolve_exec_container_id(conn.state.clone(), &version_prefix, exec_id).await {
                Ok(value) => value,
                Err(resp) => return *resp,
            };

        if let Err(resp) =
            authorize_container(conn.state.clone(), &version_prefix, &container_id, &id).await
        {
            return *resp;
        }

        if wants_upgrade(&req) {
            return forward_with_upgrade(req, conn.state.clone()).await;
        }
        return forward(req, conn.state.clone()).await;
    }

    if segs.len() >= 2 && segs[0] == "containers" {
        let second = &segs[1];
        if second != "create" && second != "json" && second != "prune" {
            let container = second;
            if let Err(resp) =
                authorize_container(conn.state.clone(), &version_prefix, container, &id).await
            {
                return *resp;
            }
            if wants_upgrade(&req) {
                return forward_with_upgrade(req, conn.state.clone()).await;
            }
            return forward(req, conn.state.clone()).await;
        }
    }

    if segs.len() >= 2 && segs[0] == "networks" {
        let second = &segs[1];
        if second != "create" && second != "prune" {
            if segs.len() >= 3 && (segs[2] == "connect" || segs[2] == "disconnect") {
                return docker_error(
                    StatusCode::FORBIDDEN,
                    "network connect/disconnect is not allowed by gateway policy",
                );
            }
            let network = second;
            if let Err(resp) =
                authorize_network(conn.state.clone(), &version_prefix, network, &id).await
            {
                return *resp;
            }
            return forward(req, conn.state.clone()).await;
        }
    }

    if segs.len() >= 2 && segs[0] == "volumes" {
        let second = &segs[1];
        if second != "create" && second != "prune" {
            let volume = second;
            if let Err(resp) =
                authorize_volume(conn.state.clone(), &version_prefix, volume, &id).await
            {
                return *resp;
            }
            return forward(req, conn.state.clone()).await;
        }
    }

    docker_error(
        StatusCode::FORBIDDEN,
        format!(
            "endpoint {} {} is not allowed by gateway policy",
            req.method(),
            req.uri().path()
        ),
    )
}

fn is_ping(segs: &[String], method: &Method) -> bool {
    method == Method::GET && segs.len() == 1 && segs[0] == "_ping"
}

fn is_version(segs: &[String], method: &Method) -> bool {
    method == Method::GET && segs.len() == 1 && segs[0] == "version"
}

fn owner_label_pairs(state: &State, id: &CallerIdentity) -> Vec<(String, String)> {
    vec![
        (AMBER_COMPONENT_LABEL.to_string(), id.component.clone()),
        (
            COMPOSE_PROJECT_LABEL.to_string(),
            state.cfg.compose_project.clone(),
        ),
    ]
}

fn required_label_filters(state: &State, id: &CallerIdentity) -> Vec<String> {
    owner_label_pairs(state, id)
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect()
}

async fn forward(mut req: Request<ProxyBody>, state: Arc<State>) -> Response<ProxyBody> {
    if let Err(resp) = rewrite_to_docker_uri(&mut req, &state.cfg.docker_sock) {
        return *resp;
    }
    ensure_host(&mut req);

    match state.client.request(req).await {
        Ok(res) => map_response(res),
        Err(err) => docker_error(
            StatusCode::BAD_GATEWAY,
            format!("docker upstream error: {err}"),
        ),
    }
}

async fn forward_with_upgrade(
    mut req: Request<ProxyBody>,
    state: Arc<State>,
) -> Response<ProxyBody> {
    let on_client = hyper::upgrade::on(&mut req);

    if let Err(resp) = rewrite_to_docker_uri(&mut req, &state.cfg.docker_sock) {
        return *resp;
    }
    ensure_host(&mut req);

    let upstream_stream = match UnixStream::connect(&state.cfg.docker_sock).await {
        Ok(stream) => stream,
        Err(err) => {
            return docker_error(
                StatusCode::BAD_GATEWAY,
                format!("connect docker.sock failed: {err}"),
            );
        }
    };

    let io = TokioIo::new(upstream_stream);
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(value) => value,
        Err(err) => {
            return docker_error(
                StatusCode::BAD_GATEWAY,
                format!("docker handshake failed: {err}"),
            );
        }
    };

    tokio::spawn(async move {
        if let Err(err) = conn.with_upgrades().await {
            eprintln!("docker upgrade connection failed: {err}");
        }
    });

    let mut upstream_res = match sender.send_request(req).await {
        Ok(res) => res,
        Err(err) => {
            return docker_error(
                StatusCode::BAD_GATEWAY,
                format!("docker request failed: {err}"),
            );
        }
    };

    if upstream_res.status() != StatusCode::SWITCHING_PROTOCOLS {
        return map_response(upstream_res);
    }

    let on_upstream = hyper::upgrade::on(&mut upstream_res);

    let status = upstream_res.status();
    let headers = upstream_res.headers().clone();

    tokio::spawn(async move {
        let Ok(down) = on_client.await else {
            eprintln!("downstream upgrade failed");
            return;
        };
        let Ok(up) = on_upstream.await else {
            eprintln!("upstream upgrade failed");
            return;
        };

        let mut down = TokioIo::new(down);
        let mut up = TokioIo::new(up);

        if let Err(err) = tokio::io::copy_bidirectional(&mut down, &mut up).await {
            eprintln!("upgrade tunnel error: {err}");
        }
    });

    let mut resp = Response::new(box_body_from_bytes(Bytes::new()));
    *resp.status_mut() = status;
    copy_headers(resp.headers_mut(), &headers);
    resp
}

#[derive(Default)]
struct ContainerCreateRefs {
    containers: HashSet<String>,
    networks: HashSet<String>,
    volumes: HashSet<String>,
}

async fn authorize_container_create_references(
    state: Arc<State>,
    version_prefix: &str,
    body: &[u8],
    id: &CallerIdentity,
) -> GatewayResult<()> {
    let refs = parse_container_create_references(body)?;

    for container in refs.containers {
        authorize_container(state.clone(), version_prefix, &container, id).await?;
    }
    for network in refs.networks {
        authorize_network(state.clone(), version_prefix, &network, id).await?;
    }
    for volume in refs.volumes {
        authorize_volume(state.clone(), version_prefix, &volume, id).await?;
    }

    Ok(())
}

fn parse_container_create_references(body: &[u8]) -> GatewayResult<ContainerCreateRefs> {
    let request: ContainerCreateRequest = serde_json::from_slice(body)
        .map_err(|_| boxed_response(docker_error(StatusCode::BAD_REQUEST, "invalid JSON body")))?;

    let mut refs = ContainerCreateRefs::default();

    if let Some(host_config) = request.host_config {
        if let Some(network_mode) = host_config.network_mode {
            add_network_mode_reference(&network_mode, &mut refs);
        }

        for bind in host_config.binds {
            if let Some(volume) = named_volume_from_bind(&bind) {
                refs.volumes.insert(volume.to_string());
            }
        }

        for mount in host_config.mounts {
            if mount
                .mount_type
                .as_deref()
                .is_some_and(|value| value.eq_ignore_ascii_case("volume"))
                && let Some(source) = mount
                    .source
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
            {
                refs.volumes.insert(source.to_string());
            }
        }

        for value in host_config.volumes_from {
            if let Some(container) = container_ref_from_qualified_value(&value) {
                refs.containers.insert(container.to_string());
            }
        }

        for value in host_config.links {
            if let Some(container) = container_ref_from_qualified_value(&value) {
                refs.containers.insert(container.to_string());
            }
        }

        if let Some(container) = container_ref_from_mode(host_config.pid_mode.as_deref()) {
            refs.containers.insert(container.to_string());
        }
        if let Some(container) = container_ref_from_mode(host_config.ipc_mode.as_deref()) {
            refs.containers.insert(container.to_string());
        }
    }

    if let Some(networking_config) = request.networking_config {
        for network in networking_config.endpoints_config.keys() {
            let network = network.trim();
            if !network.is_empty() {
                refs.networks.insert(network.to_string());
            }
        }
    }

    Ok(refs)
}

fn add_network_mode_reference(mode: &str, refs: &mut ContainerCreateRefs) {
    let mode = mode.trim();
    if mode.is_empty() {
        return;
    }

    let builtin = matches!(
        mode.to_ascii_lowercase().as_str(),
        "default" | "bridge" | "host" | "none" | "private"
    );
    if builtin {
        return;
    }

    if let Some(container) = container_ref_from_mode(Some(mode)) {
        refs.containers.insert(container.to_string());
    } else {
        refs.networks.insert(mode.to_string());
    }
}

fn container_ref_from_mode(mode: Option<&str>) -> Option<&str> {
    mode.and_then(|value| {
        value
            .trim()
            .strip_prefix("container:")
            .map(str::trim)
            .filter(|value| !value.is_empty())
    })
}

fn container_ref_from_qualified_value(value: &str) -> Option<&str> {
    value
        .split(':')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn named_volume_from_bind(bind: &str) -> Option<&str> {
    let source = bind.split(':').next()?.trim();
    if source.is_empty() {
        return None;
    }
    if source.starts_with('/') || source.contains('/') || source == "." || source == ".." {
        return None;
    }
    Some(source)
}

async fn authorize_container(
    state: Arc<State>,
    version_prefix: &str,
    container: &str,
    id: &CallerIdentity,
) -> GatewayResult<()> {
    let compose_project = state.cfg.compose_project.clone();
    let meta = fetch_container_meta(state.clone(), version_prefix, container).await?;
    if is_owner(&meta, id, &compose_project) {
        Ok(())
    } else {
        Err(boxed_response(docker_error(
            StatusCode::FORBIDDEN,
            "not authorized for this container",
        )))
    }
}

async fn authorize_network(
    state: Arc<State>,
    version_prefix: &str,
    network: &str,
    id: &CallerIdentity,
) -> GatewayResult<()> {
    let compose_project = state.cfg.compose_project.clone();
    let meta = fetch_network_meta(state.clone(), version_prefix, network).await?;
    if is_owner(&meta, id, &compose_project) {
        Ok(())
    } else {
        Err(boxed_response(docker_error(
            StatusCode::FORBIDDEN,
            "not authorized for this network",
        )))
    }
}

async fn authorize_volume(
    state: Arc<State>,
    version_prefix: &str,
    volume: &str,
    id: &CallerIdentity,
) -> GatewayResult<()> {
    let compose_project = state.cfg.compose_project.clone();
    let meta = fetch_volume_meta(state.clone(), version_prefix, volume).await?;
    if is_owner(&meta, id, &compose_project) {
        Ok(())
    } else {
        Err(boxed_response(docker_error(
            StatusCode::FORBIDDEN,
            "not authorized for this volume",
        )))
    }
}

async fn fetch_container_meta(
    state: Arc<State>,
    version_prefix: &str,
    container: &str,
) -> GatewayResult<OwnerMeta> {
    let path = with_version(version_prefix, &format!("/containers/{container}/json"));
    let response = docker_get(&state, &path).await?;
    if response.status != StatusCode::OK {
        return Err(boxed_response(response_from_upstream(
            response.status,
            response.headers,
            response.body,
        )));
    }

    let parsed: ContainerInspectResponse =
        serde_json::from_slice(&response.body).map_err(|_| {
            boxed_response(docker_error(
                StatusCode::BAD_GATEWAY,
                "unexpected inspect JSON",
            ))
        })?;

    let labels = parsed
        .config
        .and_then(|config| config.labels)
        .unwrap_or_default();

    let meta = OwnerMeta {
        component: labels.get(AMBER_COMPONENT_LABEL).cloned(),
        compose_project: labels.get(COMPOSE_PROJECT_LABEL).cloned(),
    };

    Ok(meta)
}

async fn fetch_network_meta(
    state: Arc<State>,
    version_prefix: &str,
    network: &str,
) -> GatewayResult<OwnerMeta> {
    let path = with_version(version_prefix, &format!("/networks/{network}"));
    let response = docker_get(&state, &path).await?;
    if response.status != StatusCode::OK {
        return Err(boxed_response(response_from_upstream(
            response.status,
            response.headers,
            response.body,
        )));
    }

    let parsed: NetworkInspectResponse = serde_json::from_slice(&response.body).map_err(|_| {
        boxed_response(docker_error(
            StatusCode::BAD_GATEWAY,
            "unexpected network inspect JSON",
        ))
    })?;

    let labels = parsed.labels.unwrap_or_default();
    let meta = OwnerMeta {
        component: labels.get(AMBER_COMPONENT_LABEL).cloned(),
        compose_project: labels.get(COMPOSE_PROJECT_LABEL).cloned(),
    };

    Ok(meta)
}

async fn fetch_volume_meta(
    state: Arc<State>,
    version_prefix: &str,
    volume: &str,
) -> GatewayResult<OwnerMeta> {
    let path = with_version(version_prefix, &format!("/volumes/{volume}"));
    let response = docker_get(&state, &path).await?;
    if response.status != StatusCode::OK {
        return Err(boxed_response(response_from_upstream(
            response.status,
            response.headers,
            response.body,
        )));
    }

    let parsed: VolumeInspectResponse = serde_json::from_slice(&response.body).map_err(|_| {
        boxed_response(docker_error(
            StatusCode::BAD_GATEWAY,
            "unexpected volume inspect JSON",
        ))
    })?;

    let labels = parsed.labels.unwrap_or_default();
    let meta = OwnerMeta {
        component: labels.get(AMBER_COMPONENT_LABEL).cloned(),
        compose_project: labels.get(COMPOSE_PROJECT_LABEL).cloned(),
    };

    Ok(meta)
}

async fn resolve_exec_container_id(
    state: Arc<State>,
    version_prefix: &str,
    exec_id: &str,
) -> GatewayResult<String> {
    if let Some(entry) = state.exec_map.get(exec_id) {
        return Ok(entry.value().clone());
    }

    let path = with_version(version_prefix, &format!("/exec/{exec_id}/json"));
    let response = docker_get(&state, &path).await?;
    if response.status != StatusCode::OK {
        return Err(boxed_response(response_from_upstream(
            response.status,
            response.headers,
            response.body,
        )));
    }

    let parsed: ExecInspectResponse = serde_json::from_slice(&response.body).map_err(|_| {
        boxed_response(docker_error(
            StatusCode::BAD_GATEWAY,
            "unexpected exec inspect JSON",
        ))
    })?;

    state
        .exec_map
        .insert(exec_id.to_string(), parsed.container_id.clone());

    Ok(parsed.container_id)
}

fn is_owner(meta: &OwnerMeta, id: &CallerIdentity, compose_project: &str) -> bool {
    meta.component.as_deref() == Some(id.component.as_str())
        && meta.compose_project.as_deref() == Some(compose_project)
}

struct DockerGetResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

async fn docker_get(state: &State, path: &str) -> GatewayResult<DockerGetResponse> {
    let uri: Uri = HyperlocalUri::new(&state.cfg.docker_sock, path).into();
    let mut req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(box_body_from_bytes(Bytes::new()))
        .expect("request build");
    ensure_host(&mut req);

    let res = state.client.request(req).await.map_err(|err| {
        boxed_response(docker_error(
            StatusCode::BAD_GATEWAY,
            format!("docker request failed: {err}"),
        ))
    })?;

    let status = res.status();
    let headers = res.headers().clone();
    let collected = res.into_body().collect().await.map_err(|err| {
        boxed_response(docker_error(
            StatusCode::BAD_GATEWAY,
            format!("docker body read failed: {err}"),
        ))
    })?;

    Ok(DockerGetResponse {
        status,
        headers,
        body: collected.to_bytes(),
    })
}

fn response_from_upstream(
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
) -> Response<ProxyBody> {
    let mut resp = Response::new(box_body_from_bytes(body));
    *resp.status_mut() = status;
    copy_headers(resp.headers_mut(), &headers);
    resp
}

fn docker_error(status: StatusCode, message: impl Into<String>) -> Response<ProxyBody> {
    let body = serde_json::json!({ "message": message.into() }).to_string();
    let mut resp = Response::new(box_body_from_bytes(Bytes::from(body)));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}

fn boxed_response(resp: Response<ProxyBody>) -> Box<Response<ProxyBody>> {
    Box::new(resp)
}

fn copy_headers(dst: &mut HeaderMap, src: &HeaderMap) {
    for (key, value) in src.iter() {
        dst.insert(key, value.clone());
    }
}

fn box_body_from_incoming(body: Incoming) -> ProxyBody {
    body.map_err(box_error).boxed()
}

fn box_body_from_bytes(bytes: Bytes) -> ProxyBody {
    Full::new(bytes).map_err(infallible_to_box_error).boxed()
}

fn box_error<E>(err: E) -> BoxError
where
    E: std::error::Error + Send + Sync + 'static,
{
    Box::new(err)
}

fn infallible_to_box_error(err: std::convert::Infallible) -> BoxError {
    match err {}
}

fn set_content_length(req: &mut Request<ProxyBody>, len: usize) {
    req.headers_mut().remove(header::CONTENT_LENGTH);
    req.headers_mut().remove(header::TRANSFER_ENCODING);
    let _ = req.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&len.to_string()).unwrap(),
    );
}

fn is_version_segment(seg: &str) -> bool {
    if !seg.starts_with('v') {
        return false;
    }
    let rest = &seg[1..];
    let mut parts = rest.split('.');
    let Some(a) = parts.next() else { return false };
    let Some(b) = parts.next() else { return false };
    if parts.next().is_some() {
        return false;
    }
    a.chars().all(|c| c.is_ascii_digit()) && b.chars().all(|c| c.is_ascii_digit())
}

fn split_version_and_segments(path: &str) -> (Option<String>, Vec<String>) {
    let segments: Vec<&str> = path.split('/').filter(|seg| !seg.is_empty()).collect();
    if segments.first().copied().is_some_and(is_version_segment) {
        let version = Some(format!("/{}", segments[0]));
        let rest = segments[1..].iter().map(|seg| seg.to_string()).collect();
        (version, rest)
    } else {
        (None, segments.iter().map(|seg| seg.to_string()).collect())
    }
}

fn with_version(prefix: &str, path: &str) -> String {
    if prefix.is_empty() {
        path.to_string()
    } else {
        format!("{prefix}{path}")
    }
}

fn path_and_query_str(uri: &Uri) -> String {
    uri.path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| uri.path().to_string())
}

fn rewrite_to_docker_uri(req: &mut Request<ProxyBody>, docker_sock: &PathBuf) -> GatewayResult<()> {
    let pq = path_and_query_str(req.uri());
    let docker_uri: Uri = HyperlocalUri::new(docker_sock, &pq).into();
    *req.uri_mut() = docker_uri;
    Ok(())
}

fn ensure_host(req: &mut Request<ProxyBody>) {
    if !req.headers().contains_key(header::HOST) {
        let _ = req
            .headers_mut()
            .insert(header::HOST, HeaderValue::from_static("docker"));
    }
}

fn add_label_filters_to_uri(uri: &Uri, required: &[String]) -> GatewayResult<Uri> {
    let path = uri.path().to_string();
    let mut pairs: Vec<(String, String)> = uri
        .query()
        .map(|query| {
            form_urlencoded::parse(query.as_bytes())
                .into_owned()
                .collect()
        })
        .unwrap_or_default();

    let mut filters: serde_json::Value = serde_json::Value::Object(Default::default());
    if let Some(idx) = pairs.iter().position(|(key, _)| key == "filters") {
        let raw = &pairs[idx].1;
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) {
            filters = value;
        }
    }

    if !filters.is_object() {
        filters = serde_json::Value::Object(Default::default());
    }

    let obj = filters.as_object_mut().unwrap();
    let labels_val = obj
        .entry("label")
        .or_insert_with(|| serde_json::Value::Array(vec![]));
    merge_required_labels(labels_val, required)?;

    let new_filters = serde_json::to_string(&filters).map_err(|err| {
        boxed_response(docker_error(
            StatusCode::BAD_REQUEST,
            format!("filters json error: {err}"),
        ))
    })?;

    if let Some(idx) = pairs.iter().position(|(key, _)| key == "filters") {
        pairs[idx].1 = new_filters;
    } else {
        pairs.push(("filters".to_string(), new_filters));
    }

    let new_query = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();

    let path_and_query = if new_query.is_empty() {
        path
    } else {
        format!("{path}?{new_query}")
    };

    Uri::builder()
        .path_and_query(path_and_query)
        .build()
        .map_err(|err| {
            boxed_response(docker_error(
                StatusCode::BAD_REQUEST,
                format!("uri build error: {err}"),
            ))
        })
}

fn merge_required_labels(
    labels_val: &mut serde_json::Value,
    required: &[String],
) -> GatewayResult<()> {
    match labels_val {
        serde_json::Value::Array(arr) => {
            let mut existing = HashSet::new();
            for value in arr.iter() {
                if let Some(label) = value.as_str() {
                    existing.insert(label.to_string());
                }
            }

            for label in required {
                if existing.insert(label.clone()) {
                    arr.push(serde_json::Value::String(label.clone()));
                }
            }
            Ok(())
        }
        serde_json::Value::Object(obj) => {
            for label in required {
                obj.entry(label.clone())
                    .or_insert(serde_json::Value::Bool(true));
            }
            Ok(())
        }
        serde_json::Value::String(existing_label) => {
            let mut labels = vec![serde_json::Value::String(existing_label.clone())];
            let mut seen = HashSet::from([existing_label.clone()]);
            for label in required {
                if seen.insert(label.clone()) {
                    labels.push(serde_json::Value::String(label.clone()));
                }
            }
            *labels_val = serde_json::Value::Array(labels);
            Ok(())
        }
        serde_json::Value::Null => {
            *labels_val = serde_json::Value::Array(
                required
                    .iter()
                    .cloned()
                    .map(serde_json::Value::String)
                    .collect(),
            );
            Ok(())
        }
        _ => Err(boxed_response(docker_error(
            StatusCode::BAD_REQUEST,
            "filters.label must be an array, object, string, or null",
        ))),
    }
}

fn inject_labels_into_create_body(
    body: Bytes,
    to_set: &[(String, String)],
) -> GatewayResult<Bytes> {
    let mut value: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| boxed_response(docker_error(StatusCode::BAD_REQUEST, "invalid JSON body")))?;

    let obj = value.as_object_mut().ok_or_else(|| {
        boxed_response(docker_error(
            StatusCode::BAD_REQUEST,
            "expected JSON object body",
        ))
    })?;

    let labels_val = obj
        .entry("Labels")
        .or_insert_with(|| serde_json::Value::Object(Default::default()));

    let labels_obj = labels_val.as_object_mut().ok_or_else(|| {
        boxed_response(docker_error(
            StatusCode::BAD_REQUEST,
            "Labels must be a JSON object",
        ))
    })?;

    for (key, value) in to_set {
        labels_obj.insert(key.clone(), serde_json::Value::String(value.clone()));
    }

    let out = serde_json::to_vec(&value).map_err(|err| {
        boxed_response(docker_error(
            StatusCode::BAD_REQUEST,
            format!("json encode error: {err}"),
        ))
    })?;
    Ok(Bytes::from(out))
}

fn wants_upgrade(req: &Request<ProxyBody>) -> bool {
    let conn_has_upgrade = req
        .headers()
        .get(header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
        });

    conn_has_upgrade || req.headers().contains_key(header::UPGRADE)
}

fn map_response(res: Response<Incoming>) -> Response<ProxyBody> {
    let (parts, body) = res.into_parts();
    let body = box_body_from_incoming(body);
    Response::from_parts(parts, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_version_and_segments_parses_version_prefix() {
        let (version, segments) = split_version_and_segments("/v1.41/containers/json");
        assert_eq!(version.as_deref(), Some("/v1.41"));
        assert_eq!(segments, vec!["containers", "json"]);
    }

    #[test]
    fn split_version_and_segments_handles_unversioned() {
        let (version, segments) = split_version_and_segments("/containers/json");
        assert!(version.is_none());
        assert_eq!(segments, vec!["containers", "json"]);
    }

    #[test]
    fn inject_labels_adds_missing_labels() {
        let body = Bytes::from(r#"{"Image":"busybox"}"#);
        let labels = vec![("com.example.owner".to_string(), "alice".to_string())];
        let out = inject_labels_into_create_body(body, &labels).expect("inject labels");
        let parsed: serde_json::Value = serde_json::from_slice(&out).expect("valid json");
        let labels = parsed
            .get("Labels")
            .and_then(|value| value.as_object())
            .expect("labels object");
        assert_eq!(
            labels.get("com.example.owner").and_then(|v| v.as_str()),
            Some("alice")
        );
    }

    #[test]
    fn add_label_filters_to_uri_merges_filters() {
        let uri: Uri = "/containers/json?filters=%7B%22label%22%3A%5B%22a%3Db%22%5D%7D"
            .parse()
            .expect("uri");
        let required = vec!["c=d".to_string()];
        let out = add_label_filters_to_uri(&uri, &required).expect("filters");
        let query = out.query().expect("query");
        assert!(query.contains("filters="));
    }

    #[test]
    fn add_label_filters_to_uri_accepts_object_labels() {
        let uri: Uri = "/containers/json?filters=%7B%22label%22%3A%7B%22a%3Db%22%3Atrue%7D%7D"
            .parse()
            .expect("uri");
        let required = vec!["c=d".to_string()];
        let out = add_label_filters_to_uri(&uri, &required).expect("filters");
        let query = out.query().expect("query");
        let parsed_query: HashMap<String, String> = form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
        let filters = parsed_query.get("filters").expect("filters");
        let parsed_filters: serde_json::Value = serde_json::from_str(filters).expect("json");
        let labels = parsed_filters
            .get("label")
            .and_then(|value| value.as_object())
            .expect("labels object");
        assert_eq!(labels.get("a=b"), Some(&serde_json::Value::Bool(true)));
        assert_eq!(labels.get("c=d"), Some(&serde_json::Value::Bool(true)));
    }

    #[test]
    fn parse_container_create_references_extracts_resources() {
        let body = br#"{
            "HostConfig": {
                "NetworkMode": "app-net",
                "Binds": ["shared-vol:/data", "/tmp:/tmp", ".:/workspace"],
                "Mounts": [
                    {"Type": "volume", "Source": "db-vol"},
                    {"Type": "bind", "Source": "/host"}
                ],
                "VolumesFrom": ["base-container:ro"],
                "Links": ["linked-container:alias"],
                "PidMode": "container:pid-target",
                "IpcMode": "container:ipc-target"
            },
            "NetworkingConfig": {
                "EndpointsConfig": {
                    "side-net": {}
                }
            }
        }"#;
        let refs = parse_container_create_references(body).expect("refs");
        assert!(refs.networks.contains("app-net"));
        assert!(refs.networks.contains("side-net"));
        assert!(refs.volumes.contains("shared-vol"));
        assert!(refs.volumes.contains("db-vol"));
        assert!(refs.containers.contains("base-container"));
        assert!(refs.containers.contains("linked-container"));
        assert!(refs.containers.contains("pid-target"));
        assert!(refs.containers.contains("ipc-target"));
    }
}
