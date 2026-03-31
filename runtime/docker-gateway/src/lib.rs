use std::{
    collections::{HashMap, HashSet},
    env,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use base64::Engine as _;
use bytes::Bytes;
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
use moka::sync::Cache;
use serde::{Deserialize, de::DeserializeOwned};
use serde_with::{DefaultOnNull, serde_as};
use thiserror::Error;
use tokio::{
    net::{TcpListener, UnixStream},
    sync::RwLock,
    time::{sleep, timeout},
};

const CONFIG_B64_ENV: &str = "AMBER_DOCKER_GATEWAY_CONFIG_B64";
const CONFIG_JSON_ENV: &str = "AMBER_DOCKER_GATEWAY_CONFIG_JSON";
const COMPOSE_PROJECT_LABEL: &str = "com.docker.compose.project";
#[cfg(test)]
const COMPOSE_SERVICE_LABEL: &str = "com.docker.compose.service";
const AMBER_COMPONENT_LABEL: &str = "amber.component";
const AMBER_PROJECT_LABEL: &str = "amber.project";
const CALLER_REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const SHUTDOWN_CLEANUP_TIMEOUT: Duration = Duration::from_secs(8);
const EXEC_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
const EXEC_CACHE_MAX_ENTRIES: u64 = 8_192;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type ProxyBody = BoxBody<Bytes, BoxError>;
type GatewayResult<T> = Result<T, Box<Response<ProxyBody>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShutdownReason {
    Interrupt,
    Terminated,
}

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
    pub host: String,
    #[serde(default)]
    pub port: Option<u16>,
    pub component: String,
    pub compose_service: String,
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
    exec_map: Cache<String, String>,
    callers_by_ip: RwLock<HashMap<IpAddr, Vec<ResolvedCaller>>>,
}

#[derive(Clone, Debug)]
struct OwnerMeta {
    component: Option<String>,
    project: Option<String>,
}

#[derive(Clone, Debug)]
struct CallerIdentity {
    component: String,
}

#[derive(Clone, Debug)]
struct ResolvedCaller {
    component: String,
    port: Option<u16>,
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
struct ContainerSummaryResponse {
    #[serde(rename = "Id", default)]
    id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NetworkSummaryResponse {
    #[serde(rename = "Id", default)]
    id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VolumeListResponse {
    #[serde(rename = "Volumes", default)]
    volumes: Option<Vec<VolumeSummaryResponse>>,
}

#[derive(Debug, Deserialize)]
struct VolumeSummaryResponse {
    #[serde(rename = "Name", default)]
    name: Option<String>,
}

fn cleanup_target_name(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn parse_cleanup_ids<T>(
    body: &[u8],
    id_of: impl Fn(T) -> Option<String>,
) -> Result<Vec<String>, serde_json::Error>
where
    T: DeserializeOwned,
{
    let resources = serde_json::from_slice::<Vec<T>>(body)?;
    Ok(resources.into_iter().filter_map(id_of).collect())
}

fn parse_cleanup_container_ids(body: &[u8]) -> Result<Vec<String>, serde_json::Error> {
    parse_cleanup_ids::<ContainerSummaryResponse>(body, |container| {
        cleanup_target_name(container.id.as_deref())
    })
}

fn parse_cleanup_network_ids(body: &[u8]) -> Result<Vec<String>, serde_json::Error> {
    parse_cleanup_ids::<NetworkSummaryResponse>(body, |network| {
        cleanup_target_name(network.id.as_deref())
    })
}

fn parse_cleanup_volume_names(body: &[u8]) -> Result<Vec<String>, serde_json::Error> {
    let volumes = serde_json::from_slice::<VolumeListResponse>(body)?
        .volumes
        .unwrap_or_default();
    Ok(volumes
        .into_iter()
        .filter_map(|volume| cleanup_target_name(volume.name.as_deref()))
        .collect())
}

fn cleanup_delete_container_path(id: &str) -> String {
    format!("/containers/{id}?force=1&v=1")
}

fn cleanup_delete_network_path(id: &str) -> String {
    format!("/networks/{id}")
}

fn cleanup_delete_volume_path(name: &str) -> String {
    format!("/volumes/{name}?force=1")
}

fn is_allowed_cleanup_delete_status(status: StatusCode) -> bool {
    status.is_success() || status == StatusCode::NOT_FOUND || status == StatusCode::CONFLICT
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ContainerCreateRequest {
    #[serde(default)]
    host_config: Option<HostConfigRequest>,
    #[serde(default)]
    networking_config: Option<NetworkingConfigRequest>,
}

#[serde_as]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct HostConfigRequest {
    #[serde(default)]
    network_mode: Option<String>,
    #[serde(default)]
    #[serde_as(deserialize_as = "DefaultOnNull")]
    binds: Vec<String>,
    #[serde(default)]
    #[serde_as(deserialize_as = "DefaultOnNull")]
    mounts: Vec<MountRequest>,
    #[serde(default)]
    #[serde_as(deserialize_as = "DefaultOnNull")]
    volumes_from: Vec<String>,
    #[serde(default)]
    #[serde_as(deserialize_as = "DefaultOnNull")]
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

#[serde_as]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct NetworkingConfigRequest {
    #[serde(default)]
    #[serde_as(deserialize_as = "DefaultOnNull")]
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
        for caller in &config.callers {
            if caller.host.trim().is_empty() {
                return Err(DockerGatewayError::InvalidConfig(
                    "caller host must not be empty".to_string(),
                ));
            }
            if caller.component.trim().is_empty() {
                return Err(DockerGatewayError::InvalidConfig(
                    "caller component must not be empty".to_string(),
                ));
            }
            if caller.compose_service.trim().is_empty() {
                return Err(DockerGatewayError::InvalidConfig(
                    "caller compose_service must not be empty".to_string(),
                ));
            }
        }
        Ok(config)
    }
}

impl State {
    fn new(config: DockerGatewayConfig) -> Self {
        let connector = UnixConnector;
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Self {
            cfg: Arc::new(config),
            client,
            exec_map: Cache::builder()
                .time_to_live(EXEC_CACHE_TTL)
                .max_capacity(EXEC_CACHE_MAX_ENTRIES)
                .build(),
            callers_by_ip: RwLock::new(HashMap::new()),
        }
    }

    async fn refresh_callers(&self) {
        let mut callers_by_ip: HashMap<IpAddr, Vec<ResolvedCaller>> = HashMap::new();

        for caller in &self.cfg.callers {
            match tokio::net::lookup_host((caller.host.as_str(), 0)).await {
                Ok(addrs) => {
                    let mut saw_address = false;
                    for addr in addrs {
                        saw_address = true;
                        callers_by_ip
                            .entry(addr.ip())
                            .or_default()
                            .push(ResolvedCaller {
                                component: caller.component.clone(),
                                port: caller.port,
                            });
                    }

                    if !saw_address {
                        tracing::warn!(
                            "docker gateway caller resolution returned no addresses for host {}",
                            caller.host
                        );
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        "docker gateway caller resolution failed for host {}: {err}",
                        caller.host
                    );
                }
            }
        }

        *self.callers_by_ip.write().await = callers_by_ip;
    }

    async fn resolve_identity(&self, peer: SocketAddr) -> Option<CallerIdentity> {
        let callers = self.callers_by_ip.read().await;
        let matches = callers.get(&peer.ip())?;

        let mut identity: Option<&str> = None;
        for entry in matches {
            if entry.port.is_some_and(|port| port != peer.port()) {
                continue;
            }

            match identity {
                None => identity = Some(entry.component.as_str()),
                Some(component) if component == entry.component.as_str() => {}
                Some(_) => return None,
            }
        }

        identity.map(|component| CallerIdentity {
            component: component.to_string(),
        })
    }

    async fn cleanup_created_resources(&self) {
        if timeout(
            SHUTDOWN_CLEANUP_TIMEOUT,
            self.cleanup_created_resources_inner(),
        )
        .await
        .is_err()
        {
            tracing::warn!(
                "docker gateway shutdown cleanup timed out after {:?}",
                SHUTDOWN_CLEANUP_TIMEOUT
            );
        }
    }

    async fn cleanup_created_resources_inner(&self) {
        let required_labels = vec![
            format!("{AMBER_PROJECT_LABEL}={}", self.cfg.compose_project),
            AMBER_COMPONENT_LABEL.to_string(),
        ];

        let container_query = build_label_filter_query(&required_labels, true);
        let network_query = build_label_filter_query(&required_labels, false);

        self.cleanup_resources(
            format!("/containers/json?{container_query}"),
            parse_cleanup_container_ids,
            cleanup_delete_container_path,
            "containers",
            "container",
        )
        .await;
        self.cleanup_resources(
            format!("/networks?{network_query}"),
            parse_cleanup_network_ids,
            cleanup_delete_network_path,
            "networks",
            "network",
        )
        .await;
        self.cleanup_resources(
            format!("/volumes?{network_query}"),
            parse_cleanup_volume_names,
            cleanup_delete_volume_path,
            "volumes",
            "volume",
        )
        .await;
    }

    async fn cleanup_resources(
        &self,
        list_path: String,
        parse_targets: fn(&[u8]) -> Result<Vec<String>, serde_json::Error>,
        delete_path: fn(&str) -> String,
        list_name: &str,
        item_name: &str,
    ) {
        let response = match docker_get(self, &list_path).await {
            Ok(value) => value,
            Err(_) => return,
        };
        if response.status != StatusCode::OK {
            return;
        }

        let targets = match parse_targets(&response.body) {
            Ok(value) => value,
            Err(err) => {
                tracing::warn!("docker gateway cleanup failed to parse {list_name} list: {err}");
                return;
            }
        };

        for target in targets {
            let path = delete_path(&target);
            let Ok(delete_response) = docker_delete(self, &path).await else {
                continue;
            };
            if !is_allowed_cleanup_delete_status(delete_response.status) {
                tracing::warn!(
                    "docker gateway cleanup failed to delete {item_name} {target}: {}",
                    delete_response.status
                );
            }
        }
    }
}

async fn resolve_connection_identity(state: &State, peer: SocketAddr) -> Option<CallerIdentity> {
    if let Some(identity) = state.resolve_identity(peer).await {
        return Some(identity);
    }
    // Newly started compose networks can make caller hostnames resolvable a moment after startup.
    // Refresh once on a miss so first requests do not fail with a transient unauthorized error.
    state.refresh_callers().await;
    state.resolve_identity(peer).await
}

pub async fn run(config: DockerGatewayConfig) -> Result<(), DockerGatewayError> {
    let state = Arc::new(State::new(config));
    state.refresh_callers().await;

    let refresh_state = state.clone();
    let refresh_task = tokio::spawn(async move {
        loop {
            sleep(CALLER_REFRESH_INTERVAL).await;
            refresh_state.refresh_callers().await;
        }
    });

    let listener = TcpListener::bind(state.cfg.listen)
        .await
        .map_err(|source| DockerGatewayError::BindFailed {
            addr: state.cfg.listen,
            source,
        })?;

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            reason = &mut shutdown => {
                refresh_task.abort();
                match reason {
                    ShutdownReason::Interrupt => {
                        state.cleanup_created_resources().await;
                    }
                    ShutdownReason::Terminated => {
                        // `docker compose down` sends SIGTERM and also performs its own teardown.
                        // Skipping gateway cleanup avoids duplicate deletes and "No such container" races.
                        tracing::warn!(
                            "docker gateway received SIGTERM; skipping shutdown cleanup to avoid \
                             teardown races"
                        );
                    }
                }
                return Ok(());
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(value) => value,
                    Err(err) => {
                        tracing::warn!("docker gateway accept failed: {err}");
                        continue;
                    }
                };

                let conn_state = Arc::new(ConnState {
                    state: state.clone(),
                    peer,
                    identity: resolve_connection_identity(state.as_ref(), peer).await,
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
                        tracing::warn!("docker gateway connection failed: {err}");
                    }
                });
            }
        }
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

    if req.method() == Method::GET && segs.len() == 1 && segs[0] == "info" {
        return forward(req, conn.state.clone()).await;
    }

    // Compose may inspect image metadata even when builds are disabled (`docker compose up --no-build`).
    // Image names can include `/` (e.g. `ghcr.io/org/app:tag`), so match `/images/{name}/json`
    // by prefix/suffix instead of fixed segment length.
    if req.method() == Method::GET
        && segs.len() >= 3
        && segs[0] == "images"
        && segs[segs.len() - 1] == "json"
    {
        return forward(req, conn.state.clone()).await;
    }

    // Allow image pull (POST /images/create?fromImage=...) but block image import (fromSrc)
    // and bare requests with no query parameters.
    if req.method() == Method::POST && is_create_endpoint(&segs, "images") {
        let is_pull = req
            .uri()
            .query()
            .and_then(|q| serde_urlencoded::from_str::<Vec<(String, String)>>(q).ok())
            .map(|params| {
                params.iter().any(|(k, _)| k == "fromImage")
                    && !params.iter().any(|(k, _)| k == "fromSrc")
            })
            .unwrap_or(false);

        if is_pull {
            return forward(req, conn.state.clone()).await;
        }
        return docker_error(
            StatusCode::FORBIDDEN,
            "only image pull (fromImage) is allowed; build/import is blocked",
        );
    }

    if requires_owner_label_filters(req.method(), &segs) {
        if let Err(resp) = apply_required_label_filters(&mut req, &conn.state, &id) {
            return *resp;
        }
        return forward(req, conn.state.clone()).await;
    }

    if req.method() == Method::POST && is_create_endpoint(&segs, "containers") {
        let req = match prepare_labeled_create_request(
            req,
            conn.state.clone(),
            &id,
            Some(&version_prefix),
        )
        .await
        {
            Ok(value) => value,
            Err(resp) => return resp,
        };
        return forward(req, conn.state.clone()).await;
    }

    if req.method() == Method::POST && is_create_endpoint(&segs, "networks") {
        let req = match prepare_labeled_create_request(req, conn.state.clone(), &id, None).await {
            Ok(value) => value,
            Err(resp) => return resp,
        };
        return forward(req, conn.state.clone()).await;
    }

    if req.method() == Method::POST && is_create_endpoint(&segs, "volumes") {
        let req = match prepare_labeled_create_request(req, conn.state.clone(), &id, None).await {
            Ok(value) => value,
            Err(resp) => return resp,
        };
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

fn requires_owner_label_filters(method: &Method, segs: &[String]) -> bool {
    match *method {
        Method::GET => {
            matches!(segs, [resource, op] if resource == "containers" && op == "json")
                || matches!(segs, [resource] if resource == "events")
                || matches!(segs, [resource] if resource == "networks")
                || matches!(segs, [resource] if resource == "volumes")
        }
        Method::POST => {
            matches!(segs, [resource, op] if resource == "containers" && op == "prune")
                || matches!(segs, [resource, op] if resource == "networks" && op == "prune")
                || matches!(segs, [resource, op] if resource == "volumes" && op == "prune")
        }
        _ => false,
    }
}

fn is_create_endpoint(segs: &[String], resource: &str) -> bool {
    matches!(segs, [first, second] if first == resource && second == "create")
}

fn apply_required_label_filters(
    req: &mut Request<ProxyBody>,
    state: &State,
    id: &CallerIdentity,
) -> GatewayResult<()> {
    let required = required_label_filters(state, id);
    let new_uri = add_label_filters_to_uri(req.uri(), &required)?;
    *req.uri_mut() = new_uri;
    Ok(())
}

async fn prepare_labeled_create_request(
    req: Request<ProxyBody>,
    state: Arc<State>,
    id: &CallerIdentity,
    authorize_container_refs_version_prefix: Option<&str>,
) -> Result<Request<ProxyBody>, Response<ProxyBody>> {
    let (parts, body) = req.into_parts();
    let collected = body
        .collect()
        .await
        .map_err(|err| docker_error(StatusCode::BAD_REQUEST, format!("read body failed: {err}")))?;
    let raw = collected.to_bytes();

    if let Some(version_prefix) = authorize_container_refs_version_prefix
        && let Err(resp) =
            authorize_container_create_references(state.clone(), version_prefix, &raw, id).await
    {
        return Err(*resp);
    }

    let to_set = owner_label_pairs(&state, id);
    let new_body = inject_labels_into_create_body(raw, &to_set).map_err(|resp| *resp)?;

    let mut req = Request::from_parts(parts, box_body_from_bytes(new_body.clone()));
    set_content_length(&mut req, new_body.len());
    Ok(req)
}

fn owner_label_pairs(state: &State, id: &CallerIdentity) -> Vec<(String, String)> {
    vec![
        (AMBER_COMPONENT_LABEL.to_string(), id.component.clone()),
        (
            AMBER_PROJECT_LABEL.to_string(),
            state.cfg.compose_project.clone(),
        ),
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

fn build_label_filter_query(required_labels: &[String], include_all: bool) -> String {
    let filters = serde_json::json!({
        "label": required_labels
    });
    let encoded_filters = serde_json::to_string(&filters)
        .expect("serializing static label filter JSON should succeed");

    let mut query_pairs = Vec::new();
    if include_all {
        query_pairs.push(("all".to_string(), "1".to_string()));
    }
    query_pairs.push(("filters".to_string(), encoded_filters));

    serde_urlencoded::to_string(query_pairs)
        .expect("serializing static label query params should succeed")
}

async fn shutdown_signal() -> ShutdownReason {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => ShutdownReason::Interrupt,
                    _ = sigterm.recv() => ShutdownReason::Terminated,
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                ShutdownReason::Interrupt
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        return ShutdownReason::Interrupt;
    }
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
            tracing::warn!("docker upgrade connection failed: {err}");
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
            tracing::warn!("downstream upgrade failed");
            return;
        };
        let Ok(up) = on_upstream.await else {
            tracing::warn!("upstream upgrade failed");
            return;
        };

        let mut down = TokioIo::new(down);
        let mut up = TokioIo::new(up);

        if let Err(err) = tokio::io::copy_bidirectional(&mut down, &mut up).await {
            tracing::warn!("upgrade tunnel error: {err}");
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
    let request: ContainerCreateRequest = serde_json::from_slice(body).map_err(|err| {
        boxed_response(docker_error(
            StatusCode::BAD_REQUEST,
            format!(
                "invalid JSON body: {err}; body prefix: {:?}",
                String::from_utf8_lossy(&body[..body.len().min(256)])
            ),
        ))
    })?;

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

        for value in host_config
            .volumes_from
            .into_iter()
            .chain(host_config.links)
        {
            if let Some(container) = container_ref_from_qualified_value(&value) {
                refs.containers.insert(container.to_string());
            }
        }

        for mode in [
            host_config.pid_mode.as_deref(),
            host_config.ipc_mode.as_deref(),
        ] {
            if let Some(container) = container_ref_from_mode(mode) {
                refs.containers.insert(container.to_string());
            }
        }
    }

    if let Some(networking_config) = request.networking_config {
        for network in networking_config.endpoints_config.keys() {
            let network = network.trim();
            if !network.is_empty() {
                let builtin = matches!(
                    network.to_ascii_lowercase().as_str(),
                    "default" | "bridge" | "host" | "private"
                );
                if !builtin {
                    refs.networks.insert(network.to_string());
                }
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
    let meta = fetch_container_meta(state.clone(), version_prefix, container).await?;
    authorize_owned_resource(&state, meta, id, "not authorized for this container")
}

async fn authorize_network(
    state: Arc<State>,
    version_prefix: &str,
    network: &str,
    id: &CallerIdentity,
) -> GatewayResult<()> {
    let meta = fetch_network_meta(state.clone(), version_prefix, network).await?;
    authorize_owned_resource(&state, meta, id, "not authorized for this network")
}

async fn authorize_volume(
    state: Arc<State>,
    version_prefix: &str,
    volume: &str,
    id: &CallerIdentity,
) -> GatewayResult<()> {
    let meta = fetch_volume_meta(state.clone(), version_prefix, volume).await?;
    authorize_owned_resource(&state, meta, id, "not authorized for this volume")
}

fn authorize_owned_resource(
    state: &State,
    meta: OwnerMeta,
    id: &CallerIdentity,
    denied_message: &'static str,
) -> GatewayResult<()> {
    if is_owner(&meta, id, &state.cfg.compose_project) {
        Ok(())
    } else {
        Err(boxed_response(docker_error(
            StatusCode::FORBIDDEN,
            denied_message,
        )))
    }
}

fn owner_meta_from_labels(labels: HashMap<String, String>) -> OwnerMeta {
    OwnerMeta {
        component: labels.get(AMBER_COMPONENT_LABEL).cloned(),
        project: labels.get(AMBER_PROJECT_LABEL).cloned(),
    }
}

async fn fetch_owner_meta<T>(
    state: Arc<State>,
    path: String,
    parse_error: &'static str,
    labels: impl FnOnce(T) -> Option<HashMap<String, String>>,
) -> GatewayResult<OwnerMeta>
where
    T: DeserializeOwned,
{
    let response = docker_get(&state, &path).await?;
    if response.status != StatusCode::OK {
        return Err(boxed_response(response_from_upstream(
            response.status,
            response.headers,
            response.body,
        )));
    }

    let parsed: T = serde_json::from_slice(&response.body)
        .map_err(|_| boxed_response(docker_error(StatusCode::BAD_GATEWAY, parse_error)))?;
    Ok(owner_meta_from_labels(labels(parsed).unwrap_or_default()))
}

async fn fetch_container_meta(
    state: Arc<State>,
    version_prefix: &str,
    container: &str,
) -> GatewayResult<OwnerMeta> {
    let path = with_version(version_prefix, &format!("/containers/{container}/json"));
    fetch_owner_meta(
        state,
        path,
        "unexpected inspect JSON",
        |parsed: ContainerInspectResponse| parsed.config.and_then(|config| config.labels),
    )
    .await
}

async fn fetch_network_meta(
    state: Arc<State>,
    version_prefix: &str,
    network: &str,
) -> GatewayResult<OwnerMeta> {
    let path = with_version(version_prefix, &format!("/networks/{network}"));
    fetch_owner_meta(
        state,
        path,
        "unexpected network inspect JSON",
        |parsed: NetworkInspectResponse| parsed.labels,
    )
    .await
}

async fn fetch_volume_meta(
    state: Arc<State>,
    version_prefix: &str,
    volume: &str,
) -> GatewayResult<OwnerMeta> {
    let path = with_version(version_prefix, &format!("/volumes/{volume}"));
    fetch_owner_meta(
        state,
        path,
        "unexpected volume inspect JSON",
        |parsed: VolumeInspectResponse| parsed.labels,
    )
    .await
}

async fn resolve_exec_container_id(
    state: Arc<State>,
    version_prefix: &str,
    exec_id: &str,
) -> GatewayResult<String> {
    if let Some(container_id) = state.exec_map.get(exec_id) {
        return Ok(container_id);
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

fn is_owner(meta: &OwnerMeta, id: &CallerIdentity, project: &str) -> bool {
    meta.component.as_deref() == Some(id.component.as_str())
        && meta.project.as_deref() == Some(project)
}

struct DockerGetResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

async fn docker_get(state: &State, path: &str) -> GatewayResult<DockerGetResponse> {
    docker_request(state, Method::GET, path).await
}

async fn docker_delete(state: &State, path: &str) -> GatewayResult<DockerGetResponse> {
    docker_request(state, Method::DELETE, path).await
}

async fn docker_request(
    state: &State,
    method: Method,
    path: &str,
) -> GatewayResult<DockerGetResponse> {
    let uri: Uri = HyperlocalUri::new(&state.cfg.docker_sock, path).into();
    let mut req = Request::builder()
        .method(method)
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
    let mut pairs: Vec<(String, String)> = match uri.query() {
        Some(query) => serde_urlencoded::from_str(query).map_err(|err| {
            boxed_response(docker_error(
                StatusCode::BAD_REQUEST,
                format!("invalid query parameters: {err}"),
            ))
        })?,
        None => Vec::new(),
    };

    let mut filters = if let Some(idx) = pairs.iter().position(|(key, _)| key == "filters") {
        let raw = &pairs[idx].1;
        serde_json::from_str::<serde_json::Value>(raw).map_err(|err| {
            boxed_response(docker_error(
                StatusCode::BAD_REQUEST,
                format!("filters must be valid JSON: {err}"),
            ))
        })?
    } else {
        serde_json::Value::Object(Default::default())
    };

    if !filters.is_object() {
        return Err(boxed_response(docker_error(
            StatusCode::BAD_REQUEST,
            "filters must be a JSON object",
        )));
    }

    let obj = filters.as_object_mut().unwrap();
    let labels_val = obj
        .entry("label")
        .or_insert_with(|| serde_json::Value::Object(Default::default()));
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

    let new_query = serde_urlencoded::to_string(&pairs).map_err(|err| {
        boxed_response(docker_error(
            StatusCode::BAD_REQUEST,
            format!("query parameter serialization error: {err}"),
        ))
    })?;

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
    let mut labels_obj = serde_json::Map::new();

    match labels_val {
        serde_json::Value::Array(values) => {
            for value in values.iter() {
                let Some(label) = value.as_str() else {
                    continue;
                };
                labels_obj.insert(label.to_string(), serde_json::Value::Bool(true));
            }
        }
        serde_json::Value::Object(values) => {
            for (label, enabled) in values.iter() {
                let Some(enabled) = enabled.as_bool() else {
                    return Err(boxed_response(docker_error(
                        StatusCode::BAD_REQUEST,
                        format!("filters.label[{label:?}] must be a boolean"),
                    )));
                };
                labels_obj.insert(label.clone(), serde_json::Value::Bool(enabled));
            }
        }
        serde_json::Value::String(existing_label) => {
            labels_obj.insert(existing_label.clone(), serde_json::Value::Bool(true));
        }
        serde_json::Value::Null => {}
        _ => {
            return Err(boxed_response(docker_error(
                StatusCode::BAD_REQUEST,
                "filters.label must be an array, object, string, or null",
            )));
        }
    }

    let normalize_compose_project = required
        .iter()
        .any(|label| label.starts_with(&format!("{COMPOSE_PROJECT_LABEL}=")));
    if normalize_compose_project {
        labels_obj.retain(|label, _| !label.starts_with(&format!("{COMPOSE_PROJECT_LABEL}=")));
    }

    for label in required {
        // Required owner labels must always be enabled.
        labels_obj.insert(label.clone(), serde_json::Value::Bool(true));
    }

    *labels_val = serde_json::Value::Object(labels_obj);
    Ok(())
}

fn inject_labels_into_create_body(
    body: Bytes,
    to_set: &[(String, String)],
) -> GatewayResult<Bytes> {
    let mut value: serde_json::Value = serde_json::from_slice(&body).map_err(|err| {
        boxed_response(docker_error(
            StatusCode::BAD_REQUEST,
            format!(
                "invalid JSON body: {err}; body prefix: {:?}",
                String::from_utf8_lossy(&body[..body.len().min(256)])
            ),
        ))
    })?;

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
mod tests;
