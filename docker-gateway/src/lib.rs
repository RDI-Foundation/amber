use std::{
    collections::{HashMap, HashSet},
    env,
    hash::Hash,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
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
use serde::{Deserialize, Deserializer};
use thiserror::Error;
use tokio::{
    net::{TcpListener, UnixStream},
    sync::RwLock,
    time::{sleep, timeout},
};
use url::form_urlencoded;

const CONFIG_B64_ENV: &str = "AMBER_DOCKER_GATEWAY_CONFIG_B64";
const CONFIG_JSON_ENV: &str = "AMBER_DOCKER_GATEWAY_CONFIG_JSON";
const COMPOSE_PROJECT_LABEL: &str = "com.docker.compose.project";
#[cfg(test)]
const COMPOSE_SERVICE_LABEL: &str = "com.docker.compose.service";
const AMBER_COMPONENT_LABEL: &str = "amber.component";
const AMBER_PROJECT_LABEL: &str = "amber.project";
const CALLER_REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const SHUTDOWN_CLEANUP_TIMEOUT: Duration = Duration::from_secs(8);

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
    exec_map: DashMap<String, String>,
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

fn parse_cleanup_container_ids(body: &[u8]) -> Result<Vec<String>, serde_json::Error> {
    let containers = serde_json::from_slice::<Vec<ContainerSummaryResponse>>(body)?;
    Ok(containers
        .into_iter()
        .filter_map(|container| cleanup_target_name(container.id.as_deref()))
        .collect())
}

fn parse_cleanup_network_ids(body: &[u8]) -> Result<Vec<String>, serde_json::Error> {
    let networks = serde_json::from_slice::<Vec<NetworkSummaryResponse>>(body)?;
    Ok(networks
        .into_iter()
        .filter_map(|network| cleanup_target_name(network.id.as_deref()))
        .collect())
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct HostConfigRequest {
    #[serde(default)]
    network_mode: Option<String>,
    #[serde(default, deserialize_with = "deserialize_vec_or_default")]
    binds: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_vec_or_default")]
    mounts: Vec<MountRequest>,
    #[serde(default, deserialize_with = "deserialize_vec_or_default")]
    volumes_from: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_vec_or_default")]
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
    #[serde(default, deserialize_with = "deserialize_map_or_default")]
    endpoints_config: HashMap<String, serde_json::Value>,
}

fn deserialize_vec_or_default<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

fn deserialize_map_or_default<'de, D, K, V>(deserializer: D) -> Result<HashMap<K, V>, D::Error>
where
    D: Deserializer<'de>,
    K: Deserialize<'de> + Eq + Hash,
    V: Deserialize<'de>,
{
    Ok(Option::<HashMap<K, V>>::deserialize(deserializer)?.unwrap_or_default())
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
            exec_map: DashMap::new(),
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
                        eprintln!(
                            "docker gateway caller resolution returned no addresses for host {}",
                            caller.host
                        );
                    }
                }
                Err(err) => {
                    eprintln!(
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
            eprintln!(
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

        let container_query = match build_label_filter_query(&required_labels, true) {
            Some(value) => value,
            None => return,
        };
        let network_query = match build_label_filter_query(&required_labels, false) {
            Some(value) => value,
            None => return,
        };

        self.cleanup_containers(&container_query).await;
        self.cleanup_networks(&network_query).await;
        self.cleanup_volumes(&network_query).await;
    }

    async fn cleanup_containers(&self, query: &str) {
        self.cleanup_resources(
            format!("/containers/json?{query}"),
            parse_cleanup_container_ids,
            cleanup_delete_container_path,
            "containers",
            "container",
        )
        .await;
    }

    async fn cleanup_networks(&self, query: &str) {
        self.cleanup_resources(
            format!("/networks?{query}"),
            parse_cleanup_network_ids,
            cleanup_delete_network_path,
            "networks",
            "network",
        )
        .await;
    }

    async fn cleanup_volumes(&self, query: &str) {
        self.cleanup_resources(
            format!("/volumes?{query}"),
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
                eprintln!("docker gateway cleanup failed to parse {list_name} list: {err}");
                return;
            }
        };

        for target in targets {
            let path = delete_path(&target);
            let Ok(delete_response) = docker_delete(self, &path).await else {
                continue;
            };
            if !is_allowed_cleanup_delete_status(delete_response.status) {
                eprintln!(
                    "docker gateway cleanup failed to delete {item_name} {target}: {}",
                    delete_response.status
                );
            }
        }
    }
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
                        eprintln!(
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
                        eprintln!("docker gateway accept failed: {err}");
                        continue;
                    }
                };

                let conn_state = Arc::new(ConnState {
                    state: state.clone(),
                    peer,
                    identity: state.resolve_identity(peer).await,
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

fn build_label_filter_query(required_labels: &[String], include_all: bool) -> Option<String> {
    let filters = serde_json::json!({
        "label": required_labels
    });
    let encoded_filters = serde_json::to_string(&filters).ok()?;
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    if include_all {
        serializer.append_pair("all", "1");
    }
    serializer.append_pair("filters", &encoded_filters);
    Some(serializer.finish())
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
    let project = state.cfg.compose_project.clone();
    let meta = fetch_container_meta(state.clone(), version_prefix, container).await?;
    if is_owner(&meta, id, &project) {
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
    let project = state.cfg.compose_project.clone();
    let meta = fetch_network_meta(state.clone(), version_prefix, network).await?;
    if is_owner(&meta, id, &project) {
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
    let project = state.cfg.compose_project.clone();
    let meta = fetch_volume_meta(state.clone(), version_prefix, volume).await?;
    if is_owner(&meta, id, &project) {
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
        project: labels.get(AMBER_PROJECT_LABEL).cloned(),
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
        project: labels.get(AMBER_PROJECT_LABEL).cloned(),
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
        project: labels.get(AMBER_PROJECT_LABEL).cloned(),
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
                let enabled = enabled.as_bool().unwrap_or(true);
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
mod tests {
    use std::{
        collections::VecDeque,
        net::{IpAddr, Ipv4Addr, SocketAddrV4},
        path::PathBuf,
        sync::{Arc, Mutex},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use http_body_util::Full;
    use hyper::client::conn::http1 as client_http1;
    use tempfile::TempDir;
    use tokio::{
        io::AsyncReadExt,
        net::{TcpSocket, TcpStream, UnixListener},
        task::JoinHandle,
        time::timeout,
    };

    use super::*;

    const TEST_COMPONENT: &str = "component-a";
    const TEST_PROJECT: &str = "scenario-test";

    #[derive(Clone, Debug, Eq, PartialEq, Hash)]
    struct RouteKey {
        method: Method,
        path: String,
    }

    #[derive(Clone, Debug)]
    struct CapturedRequest {
        method: Method,
        path: String,
        path_and_query: String,
        body: Bytes,
    }

    #[derive(Clone, Debug)]
    struct MockReply {
        status: StatusCode,
        body: Bytes,
        headers: Vec<(String, String)>,
    }

    impl MockReply {
        fn json(status: StatusCode, value: serde_json::Value) -> Self {
            Self {
                status,
                body: Bytes::from(value.to_string()),
                headers: vec![(
                    header::CONTENT_TYPE.as_str().to_string(),
                    "application/json".to_string(),
                )],
            }
        }

        fn empty(status: StatusCode) -> Self {
            Self {
                status,
                body: Bytes::new(),
                headers: vec![],
            }
        }
    }

    #[derive(Default)]
    struct MockDockerState {
        routes: Mutex<HashMap<RouteKey, VecDeque<MockReply>>>,
        requests: Mutex<Vec<CapturedRequest>>,
    }

    async fn handle_mock_request(
        req: Request<Incoming>,
        state: Arc<MockDockerState>,
    ) -> Response<Full<Bytes>> {
        let (parts, body) = req.into_parts();
        let body = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(err) => {
                let mut response = Response::new(Full::new(Bytes::from(format!(
                    "failed to read mock request body: {err}"
                ))));
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                return response;
            }
        };

        let path = parts.uri.path().to_string();
        let path_and_query = parts
            .uri
            .path_and_query()
            .map(|value| value.as_str().to_string())
            .unwrap_or_else(|| path.clone());

        state
            .requests
            .lock()
            .expect("mock requests lock")
            .push(CapturedRequest {
                method: parts.method.clone(),
                path: path.clone(),
                path_and_query,
                body,
            });

        let key = RouteKey {
            method: parts.method.clone(),
            path: path.clone(),
        };

        let reply = state
            .routes
            .lock()
            .expect("mock routes lock")
            .get_mut(&key)
            .and_then(VecDeque::pop_front)
            .unwrap_or_else(|| {
                MockReply::json(
                    StatusCode::NOT_FOUND,
                    serde_json::json!({
                        "message": format!("no mock route for {} {}", parts.method, path)
                    }),
                )
            });

        let mut response = Response::new(Full::new(reply.body));
        *response.status_mut() = reply.status;
        for (name, value) in reply.headers {
            response.headers_mut().insert(
                header::HeaderName::from_bytes(name.as_bytes()).expect("valid header name"),
                HeaderValue::from_str(&value).expect("valid header value"),
            );
        }
        response
    }

    struct MockDocker {
        _tmpdir: TempDir,
        socket_path: PathBuf,
        state: Arc<MockDockerState>,
        task: JoinHandle<()>,
    }

    impl MockDocker {
        async fn start() -> Self {
            let tmpdir = TempDir::new().expect("tempdir");
            let socket_path = tmpdir.path().join("docker.sock");
            let listener = UnixListener::bind(&socket_path).expect("bind unix listener");
            let state = Arc::new(MockDockerState::default());
            let state_for_task = state.clone();
            let task = tokio::spawn(async move {
                loop {
                    let (stream, _) = match listener.accept().await {
                        Ok(value) => value,
                        Err(err) => {
                            eprintln!("mock docker accept failed: {err}");
                            break;
                        }
                    };

                    let state = state_for_task.clone();
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        let svc = service_fn(move |req: Request<Incoming>| {
                            let state = state.clone();
                            async move {
                                Ok::<_, std::convert::Infallible>(
                                    handle_mock_request(req, state).await,
                                )
                            }
                        });

                        if let Err(err) = http1::Builder::new()
                            .serve_connection(io, svc)
                            .with_upgrades()
                            .await
                        {
                            eprintln!("mock docker connection failed: {err}");
                        }
                    });
                }
            });

            Self {
                _tmpdir: tmpdir,
                socket_path,
                state,
                task,
            }
        }

        fn enqueue_json(
            &self,
            method: Method,
            path: &str,
            status: StatusCode,
            value: serde_json::Value,
        ) {
            self.enqueue_reply(method, path, MockReply::json(status, value));
        }

        fn enqueue_empty(&self, method: Method, path: &str, status: StatusCode) {
            self.enqueue_reply(method, path, MockReply::empty(status));
        }

        fn enqueue_reply(&self, method: Method, path: &str, reply: MockReply) {
            let mut routes = self.state.routes.lock().expect("mock routes lock");
            routes
                .entry(RouteKey {
                    method,
                    path: path.to_string(),
                })
                .or_default()
                .push_back(reply);
        }

        fn requests(&self) -> Vec<CapturedRequest> {
            self.state
                .requests
                .lock()
                .expect("mock requests lock")
                .clone()
        }
    }

    impl Drop for MockDocker {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    struct GatewayHarness {
        addr: SocketAddr,
        docker: MockDocker,
        task: JoinHandle<()>,
    }

    impl GatewayHarness {
        async fn start(callers: Vec<CallerConfig>) -> Self {
            let docker = MockDocker::start().await;
            let addr = reserve_loopback_socket_addr();
            let config = DockerGatewayConfig {
                listen: addr,
                docker_sock: docker.socket_path.clone(),
                compose_project: TEST_PROJECT.to_string(),
                callers,
            };

            let task = tokio::spawn(async move {
                if let Err(err) = run(config).await {
                    panic!("gateway run failed: {err}");
                }
            });

            wait_until_gateway_listens(addr, &task).await;
            Self { addr, docker, task }
        }

        fn enqueue_json(
            &self,
            method: Method,
            path: &str,
            status: StatusCode,
            value: serde_json::Value,
        ) {
            self.docker.enqueue_json(method, path, status, value);
        }

        fn enqueue_empty(&self, method: Method, path: &str, status: StatusCode) {
            self.docker.enqueue_empty(method, path, status);
        }

        fn requests(&self) -> Vec<CapturedRequest> {
            self.docker.requests()
        }
    }

    impl Drop for GatewayHarness {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    #[derive(Debug)]
    struct GatewayResponse {
        status: StatusCode,
        body: Bytes,
    }

    struct GatewayClient {
        sender: client_http1::SendRequest<ProxyBody>,
        conn_task: JoinHandle<()>,
    }

    impl GatewayClient {
        async fn connect_from_socket(socket: TcpSocket, addr: SocketAddr) -> Self {
            let stream = socket.connect(addr).await.unwrap_or_else(|err| {
                panic!("connect from bound local source socket failed: {err}")
            });
            let io = TokioIo::new(stream);
            let (sender, conn) = client_http1::handshake(io)
                .await
                .expect("create gateway http connection");
            let conn_task = tokio::spawn(async move {
                if let Err(err) = conn.with_upgrades().await {
                    eprintln!("gateway test client connection failed: {err}");
                }
            });
            Self { sender, conn_task }
        }

        async fn request(
            &mut self,
            method: Method,
            target: &str,
            headers: &[(&str, &str)],
            body: &[u8],
        ) -> GatewayResponse {
            let mut builder = Request::builder()
                .method(method)
                .uri(target)
                .header(header::HOST, "gateway");
            for (name, value) in headers {
                builder = builder.header(*name, *value);
            }
            let req = builder
                .body(box_body_from_bytes(Bytes::copy_from_slice(body)))
                .expect("build gateway request");

            let response = self
                .sender
                .send_request(req)
                .await
                .expect("send request to gateway");
            let status = response.status();
            let body = response
                .into_body()
                .collect()
                .await
                .expect("read gateway response body")
                .to_bytes();
            GatewayResponse { status, body }
        }

        async fn request_with_upgrade(
            &mut self,
            method: Method,
            target: &str,
            headers: &[(&str, &str)],
            body: &[u8],
        ) -> GatewayResponse {
            let mut builder = Request::builder()
                .method(method)
                .uri(target)
                .header(header::HOST, "gateway");
            for (name, value) in headers {
                builder = builder.header(*name, *value);
            }
            let req = builder
                .body(box_body_from_bytes(Bytes::copy_from_slice(body)))
                .expect("build gateway request");

            let mut response = self
                .sender
                .send_request(req)
                .await
                .expect("send request to gateway");
            let status = response.status();

            if status == StatusCode::SWITCHING_PROTOCOLS {
                let upgraded = hyper::upgrade::on(&mut response)
                    .await
                    .expect("await gateway upgrade");
                let mut upgraded = TokioIo::new(upgraded);
                let mut body = Vec::new();
                timeout(Duration::from_secs(10), upgraded.read_to_end(&mut body))
                    .await
                    .expect("timed out reading upgraded stream")
                    .expect("read upgraded stream");
                return GatewayResponse {
                    status,
                    body: Bytes::from(body),
                };
            }

            let body = response
                .into_body()
                .collect()
                .await
                .expect("read gateway response body")
                .to_bytes();
            GatewayResponse { status, body }
        }
    }

    impl Drop for GatewayClient {
        fn drop(&mut self) {
            self.conn_task.abort();
        }
    }

    fn reserve_bound_loopback_socket() -> (TcpSocket, u16) {
        let socket = TcpSocket::new_v4().expect("create v4 tcp socket");
        socket
            .bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
            .expect("bind loopback tcp socket");
        let local_port = socket.local_addr().expect("socket local addr").port();
        (socket, local_port)
    }

    fn reserve_loopback_socket_addr() -> SocketAddr {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("bind temporary loopback listener");
        let addr = listener.local_addr().expect("local addr");
        drop(listener);
        addr
    }

    fn reserve_loopback_port() -> u16 {
        reserve_loopback_socket_addr().port()
    }

    async fn wait_until_gateway_listens(addr: SocketAddr, task: &JoinHandle<()>) {
        for _ in 0..400 {
            if TcpStream::connect(addr).await.is_ok() {
                return;
            }
            assert!(
                !task.is_finished(),
                "gateway task exited before listener was ready"
            );
            tokio::task::yield_now().await;
        }
        panic!("gateway listener did not come up at {addr}");
    }

    async fn send_gateway_request(
        addr: SocketAddr,
        method: Method,
        target: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> GatewayResponse {
        let stream = TcpStream::connect(addr)
            .await
            .unwrap_or_else(|err| panic!("connect to gateway failed: {err}"));
        send_gateway_request_on_stream(stream, method, target, headers, body).await
    }

    async fn send_gateway_request_from_port(
        addr: SocketAddr,
        source_port: u16,
        method: Method,
        target: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> GatewayResponse {
        let socket = TcpSocket::new_v4().expect("create v4 tcp socket");
        socket
            .bind(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::LOCALHOST,
                source_port,
            )))
            .unwrap_or_else(|err| panic!("bind local source port {source_port} failed: {err}"));
        let stream = socket.connect(addr).await.unwrap_or_else(|err| {
            panic!("connect from local source port {source_port} failed: {err}")
        });
        send_gateway_request_on_stream(stream, method, target, headers, body).await
    }

    async fn send_gateway_request_on_stream(
        stream: TcpStream,
        method: Method,
        target: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> GatewayResponse {
        let io = TokioIo::new(stream);
        let (mut sender, conn) = client_http1::handshake(io)
            .await
            .expect("create gateway http connection");
        tokio::spawn(async move {
            if let Err(err) = conn.with_upgrades().await {
                eprintln!("gateway test client connection failed: {err}");
            }
        });

        let mut builder = Request::builder()
            .method(method)
            .uri(target)
            .header(header::HOST, "gateway");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let req = builder
            .body(box_body_from_bytes(Bytes::copy_from_slice(body)))
            .expect("build gateway request");

        let response = sender
            .send_request(req)
            .await
            .expect("send request to gateway");
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("read gateway response body")
            .to_bytes();

        GatewayResponse { status, body }
    }

    fn default_caller() -> CallerConfig {
        CallerConfig {
            host: "127.0.0.1".to_string(),
            port: None,
            component: TEST_COMPONENT.to_string(),
            compose_service: TEST_COMPONENT.to_string(),
        }
    }

    fn container_labels(component: &str, project: &str) -> serde_json::Value {
        serde_json::json!({
            "Config": {
                "Labels": {
                    AMBER_COMPONENT_LABEL: component,
                    AMBER_PROJECT_LABEL: project
                }
            }
        })
    }

    fn resource_labels(component: &str, project: &str) -> serde_json::Value {
        serde_json::json!({
            "Labels": {
                AMBER_COMPONENT_LABEL: component,
                AMBER_PROJECT_LABEL: project
            }
        })
    }

    fn decode_filters(req: &CapturedRequest) -> serde_json::Value {
        let (_, query) = req
            .path_and_query
            .split_once('?')
            .expect("request should include query");
        let query_map: HashMap<String, String> = form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
        let filters = query_map.get("filters").expect("filters query param");
        serde_json::from_str(filters).expect("filters should be valid json")
    }

    fn labels_as_set(filters: &serde_json::Value) -> HashSet<String> {
        match filters.get("label").expect("label filters must exist") {
            serde_json::Value::Array(values) => values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .expect("array labels must be strings")
                        .to_string()
                })
                .collect(),
            serde_json::Value::Object(values) => values.keys().cloned().collect(),
            other => panic!("unexpected label filter format: {other}"),
        }
    }

    fn response_message(body: &Bytes) -> String {
        serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|value| {
                value
                    .get("message")
                    .and_then(|message| message.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| String::from_utf8_lossy(body).to_string())
    }

    fn response_json(body: &Bytes) -> serde_json::Value {
        serde_json::from_slice(body).expect("response body should be valid json")
    }

    fn response_json_id(body: &Bytes) -> String {
        response_json(body)
            .get("Id")
            .and_then(|value| value.as_str())
            .map(str::to_string)
            .expect("response should contain string Id")
    }

    fn parse_container_names(list_body: &Bytes) -> HashSet<String> {
        response_json(list_body)
            .as_array()
            .expect("container list should be an array")
            .iter()
            .flat_map(|entry| {
                entry
                    .get("Names")
                    .and_then(|value| value.as_array())
                    .into_iter()
                    .flatten()
                    .filter_map(|value| value.as_str())
                    .map(|name| name.trim_start_matches('/').to_string())
            })
            .collect()
    }

    fn unique_test_suffix() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        format!("{nanos}-{}", std::process::id())
    }

    fn docker_socket_for_ignored_e2e() -> Option<PathBuf> {
        if let Ok(host) = env::var("DOCKER_HOST")
            && let Some(path) = host.strip_prefix("unix://")
        {
            let path = PathBuf::from(path);
            if path.exists() {
                return Some(path);
            }
        }

        if let Ok(home) = env::var("HOME") {
            let desktop = PathBuf::from(home).join(".docker/run/docker.sock");
            if desktop.exists() {
                return Some(desktop);
            }
        }

        let default = PathBuf::from("/var/run/docker.sock");
        if default.exists() {
            Some(default)
        } else {
            None
        }
    }

    async fn docker_image_for_ignored_e2e(docker_sock: &PathBuf) -> Option<String> {
        let busybox_tag = "busybox:latest";
        let busybox_inspect = send_docker_request(
            docker_sock,
            Method::GET,
            "/images/busybox:latest/json",
            None,
        )
        .await;
        if busybox_inspect.status == StatusCode::OK {
            return Some(busybox_tag.to_string());
        }

        let busybox_pull = send_docker_request(
            docker_sock,
            Method::POST,
            "/images/create?fromImage=busybox&tag=latest",
            None,
        )
        .await;
        if busybox_pull.status.is_success() {
            let verify_busybox = send_docker_request(
                docker_sock,
                Method::GET,
                "/images/busybox:latest/json",
                None,
            )
            .await;
            if verify_busybox.status == StatusCode::OK {
                return Some(busybox_tag.to_string());
            }
        }

        let response = send_docker_request(docker_sock, Method::GET, "/images/json", None).await;
        if response.status != StatusCode::OK {
            eprintln!(
                "skipping docker daemon e2e: /images/json returned {} with body {}",
                response.status,
                String::from_utf8_lossy(&response.body)
            );
            return None;
        }

        let images = match response_json(&response.body) {
            serde_json::Value::Array(values) => values,
            other => {
                eprintln!(
                    "skipping docker daemon e2e: /images/json returned unexpected payload {other}"
                );
                return None;
            }
        };

        for image in images {
            let Some(tags) = image.get("RepoTags").and_then(|value| value.as_array()) else {
                continue;
            };
            for tag in tags {
                let Some(tag) = tag.as_str() else {
                    continue;
                };
                if tag == "<none>:<none>" {
                    continue;
                }

                let tag_lower = tag.to_ascii_lowercase();
                if tag_lower.contains("busybox")
                    || tag_lower.contains("alpine")
                    || tag_lower.contains("debian")
                    || tag_lower.contains("ubuntu")
                {
                    return Some(tag.to_string());
                }
            }
        }

        eprintln!(
            "skipping docker daemon e2e: no suitable local image found (need \
             busybox/alpine/debian/ubuntu)"
        );
        None
    }

    async fn send_docker_request(
        docker_sock: &PathBuf,
        method: Method,
        target: &str,
        body: Option<serde_json::Value>,
    ) -> GatewayResponse {
        let connector = UnixConnector;
        let client = Client::builder(TokioExecutor::new()).build(connector);
        let uri: Uri = HyperlocalUri::new(docker_sock, target).into();

        let body_bytes = body
            .as_ref()
            .map(|value| Bytes::from(value.to_string()))
            .unwrap_or_default();

        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .body(box_body_from_bytes(body_bytes.clone()))
            .expect("build direct docker request");
        ensure_host(&mut req);
        if !body_bytes.is_empty() {
            req.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            set_content_length(&mut req, body_bytes.len());
        }

        let response = client
            .request(req)
            .await
            .expect("send direct request to docker");
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("read direct docker response body")
            .to_bytes();
        GatewayResponse { status, body }
    }

    async fn docker_delete_network_best_effort(docker_sock: &PathBuf, name: &str) {
        let response = send_docker_request(
            docker_sock,
            Method::DELETE,
            &format!("/networks/{name}"),
            None,
        )
        .await;
        assert!(
            matches!(
                response.status,
                StatusCode::OK
                    | StatusCode::NO_CONTENT
                    | StatusCode::NOT_FOUND
                    | StatusCode::CONFLICT
            ),
            "unexpected network delete status for {name}: {} body={}",
            response.status,
            String::from_utf8_lossy(&response.body)
        );
    }

    async fn docker_delete_volume_best_effort(docker_sock: &PathBuf, name: &str) {
        let response = send_docker_request(
            docker_sock,
            Method::DELETE,
            &format!("/volumes/{name}?force=1"),
            None,
        )
        .await;
        assert!(
            matches!(
                response.status,
                StatusCode::OK | StatusCode::NO_CONTENT | StatusCode::NOT_FOUND
            ),
            "unexpected volume delete status for {name}: {} body={}",
            response.status,
            String::from_utf8_lossy(&response.body)
        );
    }

    async fn docker_delete_container_best_effort(docker_sock: &PathBuf, name: &str) {
        let response = send_docker_request(
            docker_sock,
            Method::DELETE,
            &format!("/containers/{name}?force=1&v=1"),
            None,
        )
        .await;
        assert!(
            matches!(
                response.status,
                StatusCode::OK
                    | StatusCode::NO_CONTENT
                    | StatusCode::NOT_FOUND
                    | StatusCode::CONFLICT
            ),
            "unexpected container delete status for {name}: {} body={}",
            response.status,
            String::from_utf8_lossy(&response.body)
        );
    }

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
        let uri: Uri = "/containers/json?filters=%7B%22label%22%3A%7B%22a%3Db%22%3Atrue%2C%22c%\
                        3Dd%22%3Afalse%7D%7D"
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
        assert_eq!(
            labels.get("a=b").and_then(|value| value.as_bool()),
            Some(true)
        );
        assert_eq!(
            labels.get("c=d").and_then(|value| value.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn add_label_filters_to_uri_uses_object_labels_with_name_filter() {
        let uri: Uri = "/networks?filters=%7B%22name%22%3A%7B%22example_net%22%3Atrue%7D%2C%\
                        22label%22%3A%7B%22existing%3Dlabel%22%3Atrue%7D%7D"
            .parse()
            .expect("uri");
        let required = vec!["amber.component=/green".to_string()];
        let out = add_label_filters_to_uri(&uri, &required).expect("filters");
        let query = out.query().expect("query");
        let parsed_query: HashMap<String, String> = form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
        let filters = parsed_query.get("filters").expect("filters");
        let parsed_filters: serde_json::Value = serde_json::from_str(filters).expect("json");

        assert!(
            parsed_filters
                .get("name")
                .and_then(|value| value.as_object())
                .is_some()
        );

        let labels = parsed_filters
            .get("label")
            .and_then(|value| value.as_object())
            .expect("labels object");
        assert_eq!(
            labels
                .get("existing=label")
                .and_then(|value| value.as_bool()),
            Some(true)
        );
        assert_eq!(
            labels
                .get("amber.component=/green")
                .and_then(|value| value.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn add_label_filters_to_uri_rewrites_compose_project_filter() {
        let uri: Uri = "/containers/json?filters=%7B%22label%22%3A%5B%22com.docker.compose.\
                        project%3Dinner-project%22%2C%22com.docker.compose.service%3Dlangchain%22%\
                        5D%7D"
            .parse()
            .expect("uri");
        let required = vec![
            "amber.component=/green".to_string(),
            "amber.project=outer-project".to_string(),
            "com.docker.compose.project=outer-project".to_string(),
        ];

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

        assert!(labels.contains_key("com.docker.compose.service=langchain"));
        assert!(labels.contains_key("com.docker.compose.project=outer-project"));
        assert!(!labels.contains_key("com.docker.compose.project=inner-project"));
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

    #[test]
    fn validate_rejects_empty_caller_host() {
        let config = DockerGatewayConfig {
            listen: "127.0.0.1:23750".parse().expect("valid listen addr"),
            docker_sock: PathBuf::from("/tmp/docker.sock"),
            compose_project: TEST_PROJECT.to_string(),
            callers: vec![CallerConfig {
                host: "   ".to_string(),
                port: None,
                component: TEST_COMPONENT.to_string(),
                compose_service: TEST_COMPONENT.to_string(),
            }],
        };

        let err = DockerGatewayConfig::validate(config).expect_err("empty host should fail");
        assert!(
            err.to_string().contains("caller host must not be empty"),
            "{err}"
        );
    }

    #[test]
    fn validate_rejects_empty_caller_component() {
        let config = DockerGatewayConfig {
            listen: "127.0.0.1:23750".parse().expect("valid listen addr"),
            docker_sock: PathBuf::from("/tmp/docker.sock"),
            compose_project: TEST_PROJECT.to_string(),
            callers: vec![CallerConfig {
                host: "localhost".to_string(),
                port: None,
                component: "   ".to_string(),
                compose_service: TEST_COMPONENT.to_string(),
            }],
        };

        let err = DockerGatewayConfig::validate(config).expect_err("empty component should fail");
        assert!(
            err.to_string()
                .contains("caller component must not be empty"),
            "{err}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_identity_uses_port_and_denies_ambiguous_component_matches() {
        let state = State::new(DockerGatewayConfig {
            listen: "127.0.0.1:23750".parse().expect("valid listen addr"),
            docker_sock: PathBuf::from("/tmp/docker.sock"),
            compose_project: TEST_PROJECT.to_string(),
            callers: vec![default_caller()],
        });

        {
            let mut callers = state.callers_by_ip.write().await;
            callers.insert(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                vec![
                    ResolvedCaller {
                        component: "component-a".to_string(),
                        port: Some(30001),
                    },
                    ResolvedCaller {
                        component: "component-b".to_string(),
                        port: Some(30002),
                    },
                ],
            );
        }

        let a = state
            .resolve_identity("127.0.0.1:30001".parse().expect("valid addr"))
            .await
            .expect("caller a should match");
        assert_eq!(a.component, "component-a");

        let b = state
            .resolve_identity("127.0.0.1:30002".parse().expect("valid addr"))
            .await
            .expect("caller b should match");
        assert_eq!(b.component, "component-b");

        let unmatched = state
            .resolve_identity("127.0.0.1:30003".parse().expect("valid addr"))
            .await;
        assert!(
            unmatched.is_none(),
            "unexpected identity for unmatched port"
        );

        {
            let mut callers = state.callers_by_ip.write().await;
            callers.insert(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                vec![
                    ResolvedCaller {
                        component: "component-a".to_string(),
                        port: None,
                    },
                    ResolvedCaller {
                        component: "component-b".to_string(),
                        port: None,
                    },
                ],
            );
        }

        let ambiguous = state
            .resolve_identity("127.0.0.1:30010".parse().expect("valid addr"))
            .await;
        assert!(
            ambiguous.is_none(),
            "ambiguous peer mapping should fail closed"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_unauthorized_peer_before_proxying() {
        let gateway = GatewayHarness::start(vec![CallerConfig {
            host: "127.0.0.2".to_string(),
            port: None,
            component: TEST_COMPONENT.to_string(),
            compose_service: TEST_COMPONENT.to_string(),
        }])
        .await;

        let response = send_gateway_request(gateway.addr, Method::GET, "/_ping", &[], &[]).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        assert!(response_message(&response.body).contains("unauthorized peer"));
        assert!(gateway.requests().is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn enforces_port_restrictions_for_authenticated_callers() {
        let allowed_port = reserve_loopback_port();
        let denied_port = reserve_loopback_port();
        assert_ne!(allowed_port, denied_port);

        let gateway = GatewayHarness::start(vec![CallerConfig {
            host: "127.0.0.1".to_string(),
            port: Some(allowed_port),
            component: TEST_COMPONENT.to_string(),
            compose_service: TEST_COMPONENT.to_string(),
        }])
        .await;
        gateway.enqueue_json(
            Method::GET,
            "/version",
            StatusCode::OK,
            serde_json::json!({"Version":"24.0"}),
        );

        let denied = send_gateway_request_from_port(
            gateway.addr,
            denied_port,
            Method::GET,
            "/version",
            &[],
            &[],
        )
        .await;
        assert_eq!(denied.status, StatusCode::UNAUTHORIZED);

        let allowed = send_gateway_request_from_port(
            gateway.addr,
            allowed_port,
            Method::GET,
            "/version",
            &[],
            &[],
        )
        .await;
        assert_eq!(allowed.status, StatusCode::OK);

        let requests = gateway.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, Method::GET);
        assert_eq!(requests[0].path, "/version");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn default_deny_blocks_unapproved_endpoints() {
        let gateway = GatewayHarness::start(vec![default_caller()]).await;

        let response =
            send_gateway_request(gateway.addr, Method::GET, "/images/json", &[], &[]).await;
        assert_eq!(response.status, StatusCode::FORBIDDEN);
        assert!(response_message(&response.body).contains("not allowed by gateway policy"));
        assert!(gateway.requests().is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn allows_image_inspect_endpoint_for_prebuilt_workflows() {
        let gateway = GatewayHarness::start(vec![default_caller()]).await;
        gateway.enqueue_json(
            Method::GET,
            "/images/busybox:latest/json",
            StatusCode::OK,
            serde_json::json!({"Id":"sha256:abc"}),
        );

        let response = send_gateway_request(
            gateway.addr,
            Method::GET,
            "/images/busybox:latest/json",
            &[],
            &[],
        )
        .await;
        assert_eq!(response.status, StatusCode::OK);

        let requests = gateway.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, Method::GET);
        assert_eq!(requests[0].path, "/images/busybox:latest/json");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn allows_image_inspect_endpoint_for_registry_qualified_names() {
        let gateway = GatewayHarness::start(vec![default_caller()]).await;
        gateway.enqueue_json(
            Method::GET,
            "/images/ghcr.io/org/app:latest/json",
            StatusCode::OK,
            serde_json::json!({"Id":"sha256:def"}),
        );

        let response = send_gateway_request(
            gateway.addr,
            Method::GET,
            "/images/ghcr.io/org/app:latest/json",
            &[],
            &[],
        )
        .await;
        assert_eq!(response.status, StatusCode::OK);

        let requests = gateway.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, Method::GET);
        assert_eq!(requests[0].path, "/images/ghcr.io/org/app:latest/json");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn allows_info_endpoint() {
        let gateway = GatewayHarness::start(vec![default_caller()]).await;
        gateway.enqueue_json(
            Method::GET,
            "/info",
            StatusCode::OK,
            serde_json::json!({"ServerVersion":"27.0"}),
        );

        let response = send_gateway_request(gateway.addr, Method::GET, "/info", &[], &[]).await;
        assert_eq!(response.status, StatusCode::OK);

        let requests = gateway.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, Method::GET);
        assert_eq!(requests[0].path, "/info");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn blocks_network_connect_and_disconnect() {
        let gateway = GatewayHarness::start(vec![default_caller()]).await;

        let connect = send_gateway_request(
            gateway.addr,
            Method::POST,
            "/networks/app-net/connect",
            &[],
            br#"{"Container":"abc"}"#,
        )
        .await;
        assert_eq!(connect.status, StatusCode::FORBIDDEN);

        let disconnect = send_gateway_request(
            gateway.addr,
            Method::POST,
            "/networks/app-net/disconnect",
            &[],
            br#"{"Container":"abc"}"#,
        )
        .await;
        assert_eq!(disconnect.status, StatusCode::FORBIDDEN);

        assert!(gateway.requests().is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_injects_owner_labels_and_normalizes_compose_project() {
        let gateway = GatewayHarness::start(vec![default_caller()]).await;
        gateway.enqueue_json(
            Method::POST,
            "/containers/create",
            StatusCode::CREATED,
            serde_json::json!({"Id":"new-container"}),
        );

        let body = serde_json::json!({
            "Image": "busybox",
            "Labels": {
                AMBER_COMPONENT_LABEL: "attacker",
                AMBER_PROJECT_LABEL: "other-project",
                COMPOSE_PROJECT_LABEL: "compose-project",
                COMPOSE_SERVICE_LABEL: "other-service",
                "user.label": "kept"
            }
        });

        let response = send_gateway_request(
            gateway.addr,
            Method::POST,
            "/containers/create",
            &[("content-type", "application/json")],
            body.to_string().as_bytes(),
        )
        .await;
        assert_eq!(response.status, StatusCode::CREATED);

        let requests = gateway.requests();
        let create_req = requests
            .iter()
            .find(|req| req.method == Method::POST && req.path == "/containers/create")
            .expect("create should be forwarded");
        let forwarded: serde_json::Value =
            serde_json::from_slice(&create_req.body).expect("forwarded body json");
        let labels = forwarded
            .get("Labels")
            .and_then(|value| value.as_object())
            .expect("forwarded labels object");
        assert_eq!(
            labels.get(AMBER_COMPONENT_LABEL).and_then(|v| v.as_str()),
            Some(TEST_COMPONENT)
        );
        assert_eq!(
            labels.get(AMBER_PROJECT_LABEL).and_then(|v| v.as_str()),
            Some(TEST_PROJECT)
        );
        assert_eq!(
            labels.get(COMPOSE_SERVICE_LABEL).and_then(|v| v.as_str()),
            Some("other-service")
        );
        assert_eq!(
            labels.get(COMPOSE_PROJECT_LABEL).and_then(|v| v.as_str()),
            Some(TEST_PROJECT)
        );
        assert_eq!(
            labels.get("user.label").and_then(|v| v.as_str()),
            Some("kept")
        );

        assert!(
            !requests
                .iter()
                .any(|req| req.method == Method::GET && req.path == "/containers/json"),
            "container create should not query compose config hash"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_rejects_foreign_network_reference() {
        let gateway = GatewayHarness::start(vec![default_caller()]).await;
        gateway.enqueue_json(
            Method::GET,
            "/networks/shared-net",
            StatusCode::OK,
            resource_labels("other-component", TEST_PROJECT),
        );

        let body = serde_json::json!({
            "Image": "busybox",
            "HostConfig": {
                "NetworkMode": "shared-net"
            }
        });

        let response = send_gateway_request(
            gateway.addr,
            Method::POST,
            "/containers/create",
            &[("content-type", "application/json")],
            body.to_string().as_bytes(),
        )
        .await;
        assert_eq!(response.status, StatusCode::FORBIDDEN);
        assert!(response_message(&response.body).contains("not authorized for this network"));

        let requests = gateway.requests();
        let paths: HashSet<&str> = requests.iter().map(|req| req.path.as_str()).collect();
        assert!(paths.contains("/networks/shared-net"));
        assert!(!paths.contains("/containers/create"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_rejects_foreign_named_volume_bind() {
        let gateway = GatewayHarness::start(vec![default_caller()]).await;
        gateway.enqueue_json(
            Method::GET,
            "/volumes/shared-volume",
            StatusCode::OK,
            resource_labels("other-component", TEST_PROJECT),
        );

        let body = serde_json::json!({
            "Image": "busybox",
            "HostConfig": {
                "Binds": ["shared-volume:/data"]
            }
        });

        let response = send_gateway_request(
            gateway.addr,
            Method::POST,
            "/containers/create",
            &[("content-type", "application/json")],
            body.to_string().as_bytes(),
        )
        .await;
        assert_eq!(response.status, StatusCode::FORBIDDEN);
        assert!(response_message(&response.body).contains("not authorized for this volume"));

        let requests = gateway.requests();
        let paths: HashSet<&str> = requests.iter().map(|req| req.path.as_str()).collect();
        assert!(paths.contains("/volumes/shared-volume"));
        assert!(!paths.contains("/containers/create"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_allows_owned_resource_references() {
        let gateway = GatewayHarness::start(vec![default_caller()]).await;
        gateway.enqueue_json(
            Method::GET,
            "/containers/base/json",
            StatusCode::OK,
            container_labels(TEST_COMPONENT, TEST_PROJECT),
        );
        gateway.enqueue_json(
            Method::GET,
            "/networks/app-net",
            StatusCode::OK,
            resource_labels(TEST_COMPONENT, TEST_PROJECT),
        );
        gateway.enqueue_json(
            Method::GET,
            "/networks/side-net",
            StatusCode::OK,
            resource_labels(TEST_COMPONENT, TEST_PROJECT),
        );
        gateway.enqueue_json(
            Method::GET,
            "/volumes/shared-vol",
            StatusCode::OK,
            resource_labels(TEST_COMPONENT, TEST_PROJECT),
        );
        gateway.enqueue_json(
            Method::POST,
            "/containers/create",
            StatusCode::CREATED,
            serde_json::json!({"Id":"ok"}),
        );

        let body = serde_json::json!({
            "Image": "busybox",
            "HostConfig": {
                "NetworkMode": "app-net",
                "Binds": ["shared-vol:/data"],
                "VolumesFrom": ["base:ro"],
                "Links": ["base:alias"],
                "PidMode": "container:base",
                "IpcMode": "container:base"
            },
            "NetworkingConfig": {
                "EndpointsConfig": {
                    "side-net": {}
                }
            }
        });

        let response = send_gateway_request(
            gateway.addr,
            Method::POST,
            "/containers/create",
            &[("content-type", "application/json")],
            body.to_string().as_bytes(),
        )
        .await;
        assert_eq!(response.status, StatusCode::CREATED);

        let requests = gateway.requests();
        let paths: HashSet<&str> = requests.iter().map(|req| req.path.as_str()).collect();
        assert!(paths.contains("/containers/base/json"));
        assert!(paths.contains("/networks/app-net"));
        assert!(paths.contains("/networks/side-net"));
        assert!(paths.contains("/volumes/shared-vol"));
        assert!(paths.contains("/containers/create"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn list_and_prune_endpoints_force_required_label_filters() {
        let gateway = GatewayHarness::start(vec![default_caller()]).await;
        gateway.enqueue_json(
            Method::GET,
            "/containers/json",
            StatusCode::OK,
            serde_json::json!([]),
        );
        gateway.enqueue_json(
            Method::POST,
            "/volumes/prune",
            StatusCode::OK,
            serde_json::json!({"VolumesDeleted":[]}),
        );

        let containers_response = send_gateway_request(
            gateway.addr,
            Method::GET,
            "/containers/json?filters=%7B%22label%22%3A%5B%22existing%3Dlabel%22%5D%7D",
            &[],
            &[],
        )
        .await;
        assert_eq!(containers_response.status, StatusCode::OK);

        let prune_response = send_gateway_request(
            gateway.addr,
            Method::POST,
            "/volumes/prune?filters=%7B%22label%22%3A%7B%22existing%3Dlabel%22%3Atrue%7D%7D",
            &[],
            &[],
        )
        .await;
        assert_eq!(prune_response.status, StatusCode::OK);

        let requests = gateway.requests();
        let containers_req = requests
            .iter()
            .find(|req| req.method == Method::GET && req.path == "/containers/json")
            .expect("containers list should be forwarded");
        let containers_filters = decode_filters(containers_req);
        let container_labels = labels_as_set(&containers_filters);
        assert!(container_labels.contains("existing=label"));
        assert!(container_labels.contains(&format!("{AMBER_COMPONENT_LABEL}={TEST_COMPONENT}")));
        assert!(container_labels.contains(&format!("{AMBER_PROJECT_LABEL}={TEST_PROJECT}")));

        let prune_req = requests
            .iter()
            .find(|req| req.method == Method::POST && req.path == "/volumes/prune")
            .expect("volumes prune should be forwarded");
        let prune_filters = decode_filters(prune_req);
        let prune_labels = labels_as_set(&prune_filters);
        assert!(prune_labels.contains("existing=label"));
        assert!(prune_labels.contains(&format!("{AMBER_COMPONENT_LABEL}={TEST_COMPONENT}")));
        assert!(prune_labels.contains(&format!("{AMBER_PROJECT_LABEL}={TEST_PROJECT}")));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn compose_in_compose_setup_injects_scoped_labels() {
        let gateway = GatewayHarness::start(vec![default_caller()]).await;
        gateway.enqueue_json(
            Method::POST,
            "/networks/create",
            StatusCode::CREATED,
            serde_json::json!({"Id":"inner-net"}),
        );
        gateway.enqueue_json(
            Method::POST,
            "/volumes/create",
            StatusCode::CREATED,
            serde_json::json!({"Name":"inner-vol"}),
        );
        gateway.enqueue_json(
            Method::POST,
            "/containers/create",
            StatusCode::CREATED,
            serde_json::json!({"Id":"inner-workload"}),
        );

        let create_network = send_gateway_request(
            gateway.addr,
            Method::POST,
            "/networks/create",
            &[("content-type", "application/json")],
            br#"{
                "Name":"inner-net",
                "Labels":{
                    "com.docker.compose.project":"inner-project",
                    "com.docker.compose.network":"default"
                }
            }"#,
        )
        .await;
        assert_eq!(create_network.status, StatusCode::CREATED);

        let create_volume = send_gateway_request(
            gateway.addr,
            Method::POST,
            "/volumes/create",
            &[("content-type", "application/json")],
            br#"{
                "Name":"inner-vol",
                "Labels":{
                    "com.docker.compose.project":"inner-project",
                    "com.docker.compose.volume":"cache"
                }
            }"#,
        )
        .await;
        assert_eq!(create_volume.status, StatusCode::CREATED);

        let create_container = send_gateway_request(
            gateway.addr,
            Method::POST,
            "/containers/create?name=inner-workload-1",
            &[("content-type", "application/json")],
            br#"{
                "Image":"busybox",
                "Labels":{
                    "com.docker.compose.project":"inner-project",
                    "com.docker.compose.service":"workload"
                }
            }"#,
        )
        .await;
        assert_eq!(create_container.status, StatusCode::CREATED);

        let requests = gateway.requests();
        let network_create = requests
            .iter()
            .find(|req| req.method == Method::POST && req.path == "/networks/create")
            .expect("network create should be forwarded");
        let network_body: serde_json::Value =
            serde_json::from_slice(&network_create.body).expect("network create body json");
        let network_labels = network_body
            .get("Labels")
            .and_then(|value| value.as_object())
            .expect("network labels object");
        assert_eq!(
            network_labels
                .get(COMPOSE_PROJECT_LABEL)
                .and_then(|value| value.as_str()),
            Some(TEST_PROJECT)
        );
        assert_eq!(
            network_labels
                .get(AMBER_COMPONENT_LABEL)
                .and_then(|value| value.as_str()),
            Some(TEST_COMPONENT)
        );
        assert_eq!(
            network_labels
                .get(AMBER_PROJECT_LABEL)
                .and_then(|value| value.as_str()),
            Some(TEST_PROJECT)
        );

        let volume_create = requests
            .iter()
            .find(|req| req.method == Method::POST && req.path == "/volumes/create")
            .expect("volume create should be forwarded");
        let volume_body: serde_json::Value =
            serde_json::from_slice(&volume_create.body).expect("volume create body json");
        let volume_labels = volume_body
            .get("Labels")
            .and_then(|value| value.as_object())
            .expect("volume labels object");
        assert_eq!(
            volume_labels
                .get(COMPOSE_PROJECT_LABEL)
                .and_then(|value| value.as_str()),
            Some(TEST_PROJECT)
        );
        assert_eq!(
            volume_labels
                .get(AMBER_COMPONENT_LABEL)
                .and_then(|value| value.as_str()),
            Some(TEST_COMPONENT)
        );
        assert_eq!(
            volume_labels
                .get(AMBER_PROJECT_LABEL)
                .and_then(|value| value.as_str()),
            Some(TEST_PROJECT)
        );

        let container_create = requests
            .iter()
            .find(|req| req.method == Method::POST && req.path == "/containers/create")
            .expect("container create should be forwarded");
        let container_body: serde_json::Value =
            serde_json::from_slice(&container_create.body).expect("container create body json");
        let container_labels = container_body
            .get("Labels")
            .and_then(|value| value.as_object())
            .expect("container labels object");
        assert_eq!(
            container_labels
                .get(COMPOSE_PROJECT_LABEL)
                .and_then(|value| value.as_str()),
            Some(TEST_PROJECT)
        );
        assert_eq!(
            container_labels
                .get(AMBER_COMPONENT_LABEL)
                .and_then(|value| value.as_str()),
            Some(TEST_COMPONENT)
        );
        assert_eq!(
            container_labels
                .get(AMBER_PROJECT_LABEL)
                .and_then(|value| value.as_str()),
            Some(TEST_PROJECT)
        );
        assert_eq!(
            container_labels
                .get(COMPOSE_SERVICE_LABEL)
                .and_then(|value| value.as_str()),
            Some("workload")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn compose_in_compose_teardown_allows_owned_resource_removal() {
        let gateway = GatewayHarness::start(vec![default_caller()]).await;
        gateway.enqueue_json(
            Method::GET,
            "/containers/inner-workload/json",
            StatusCode::OK,
            container_labels(TEST_COMPONENT, TEST_PROJECT),
        );
        gateway.enqueue_empty(
            Method::POST,
            "/containers/inner-workload/stop",
            StatusCode::OK,
        );
        gateway.enqueue_json(
            Method::GET,
            "/containers/inner-workload/json",
            StatusCode::OK,
            container_labels(TEST_COMPONENT, TEST_PROJECT),
        );
        gateway.enqueue_empty(
            Method::DELETE,
            "/containers/inner-workload",
            StatusCode::NO_CONTENT,
        );
        gateway.enqueue_json(
            Method::GET,
            "/networks/inner-net",
            StatusCode::OK,
            resource_labels(TEST_COMPONENT, TEST_PROJECT),
        );
        gateway.enqueue_empty(
            Method::DELETE,
            "/networks/inner-net",
            StatusCode::NO_CONTENT,
        );
        gateway.enqueue_json(
            Method::GET,
            "/volumes/inner-vol",
            StatusCode::OK,
            resource_labels(TEST_COMPONENT, TEST_PROJECT),
        );
        gateway.enqueue_empty(Method::DELETE, "/volumes/inner-vol", StatusCode::NO_CONTENT);

        let stop_container = send_gateway_request(
            gateway.addr,
            Method::POST,
            "/containers/inner-workload/stop?t=1",
            &[],
            &[],
        )
        .await;
        assert_eq!(stop_container.status, StatusCode::OK);

        let remove_container = send_gateway_request(
            gateway.addr,
            Method::DELETE,
            "/containers/inner-workload?v=1",
            &[],
            &[],
        )
        .await;
        assert_eq!(remove_container.status, StatusCode::NO_CONTENT);

        let remove_network = send_gateway_request(
            gateway.addr,
            Method::DELETE,
            "/networks/inner-net",
            &[],
            &[],
        )
        .await;
        assert_eq!(remove_network.status, StatusCode::NO_CONTENT);

        let remove_volume = send_gateway_request(
            gateway.addr,
            Method::DELETE,
            "/volumes/inner-vol?force=1",
            &[],
            &[],
        )
        .await;
        assert_eq!(remove_volume.status, StatusCode::NO_CONTENT);

        let requests = gateway.requests();
        let container_auth_count = requests
            .iter()
            .filter(|req| {
                req.method == Method::GET && req.path == "/containers/inner-workload/json"
            })
            .count();
        assert_eq!(container_auth_count, 2);
        assert!(
            requests
                .iter()
                .any(|req| req.method == Method::POST
                    && req.path == "/containers/inner-workload/stop")
        );
        assert!(
            requests
                .iter()
                .any(|req| req.method == Method::DELETE && req.path == "/containers/inner-workload")
        );
        assert!(
            requests
                .iter()
                .any(|req| req.method == Method::GET && req.path == "/networks/inner-net")
        );
        assert!(
            requests
                .iter()
                .any(|req| req.method == Method::DELETE && req.path == "/networks/inner-net")
        );
        assert!(
            requests
                .iter()
                .any(|req| req.method == Method::GET && req.path == "/volumes/inner-vol")
        );
        assert!(
            requests
                .iter()
                .any(|req| req.method == Method::DELETE && req.path == "/volumes/inner-vol")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn compose_in_compose_remove_orphans_rewrites_project_filters() {
        let gateway = GatewayHarness::start(vec![default_caller()]).await;
        gateway.enqueue_json(
            Method::GET,
            "/containers/json",
            StatusCode::OK,
            serde_json::json!([]),
        );
        gateway.enqueue_json(
            Method::GET,
            "/networks",
            StatusCode::OK,
            serde_json::json!([]),
        );
        gateway.enqueue_json(
            Method::GET,
            "/volumes",
            StatusCode::OK,
            serde_json::json!({"Volumes":[]}),
        );

        let inner_project = "inner-project";
        let container_query = build_label_filter_query(
            &[
                format!("{COMPOSE_PROJECT_LABEL}={inner_project}"),
                "com.docker.compose.oneoff=False".to_string(),
            ],
            true,
        )
        .expect("container filters query");
        let network_query =
            build_label_filter_query(&[format!("{COMPOSE_PROJECT_LABEL}={inner_project}")], false)
                .expect("network filters query");
        let volume_query =
            build_label_filter_query(&[format!("{COMPOSE_PROJECT_LABEL}={inner_project}")], false)
                .expect("volume filters query");

        let list_containers = send_gateway_request(
            gateway.addr,
            Method::GET,
            &format!("/containers/json?{container_query}"),
            &[],
            &[],
        )
        .await;
        assert_eq!(list_containers.status, StatusCode::OK);

        let list_networks = send_gateway_request(
            gateway.addr,
            Method::GET,
            &format!("/networks?{network_query}"),
            &[],
            &[],
        )
        .await;
        assert_eq!(list_networks.status, StatusCode::OK);

        let list_volumes = send_gateway_request(
            gateway.addr,
            Method::GET,
            &format!("/volumes?{volume_query}"),
            &[],
            &[],
        )
        .await;
        assert_eq!(list_volumes.status, StatusCode::OK);

        let requests = gateway.requests();
        let containers_req = requests
            .iter()
            .find(|req| req.method == Method::GET && req.path == "/containers/json")
            .expect("containers list should be forwarded");
        assert!(
            containers_req.path_and_query.contains("all=1"),
            "compose --remove-orphans should preserve all=1 on container listing"
        );
        let container_filters = decode_filters(containers_req);
        let container_labels = labels_as_set(&container_filters);
        assert!(container_labels.contains("com.docker.compose.oneoff=False"));
        assert!(container_labels.contains(&format!("{COMPOSE_PROJECT_LABEL}={TEST_PROJECT}")));
        assert!(!container_labels.contains(&format!("{COMPOSE_PROJECT_LABEL}={inner_project}")));
        assert!(container_labels.contains(&format!("{AMBER_COMPONENT_LABEL}={TEST_COMPONENT}")));
        assert!(container_labels.contains(&format!("{AMBER_PROJECT_LABEL}={TEST_PROJECT}")));

        let networks_req = requests
            .iter()
            .find(|req| req.method == Method::GET && req.path == "/networks")
            .expect("networks list should be forwarded");
        let network_filters = decode_filters(networks_req);
        let network_labels = labels_as_set(&network_filters);
        assert!(network_labels.contains(&format!("{COMPOSE_PROJECT_LABEL}={TEST_PROJECT}")));
        assert!(!network_labels.contains(&format!("{COMPOSE_PROJECT_LABEL}={inner_project}")));
        assert!(network_labels.contains(&format!("{AMBER_COMPONENT_LABEL}={TEST_COMPONENT}")));
        assert!(network_labels.contains(&format!("{AMBER_PROJECT_LABEL}={TEST_PROJECT}")));

        let volumes_req = requests
            .iter()
            .find(|req| req.method == Method::GET && req.path == "/volumes")
            .expect("volumes list should be forwarded");
        let volume_filters = decode_filters(volumes_req);
        let volume_labels = labels_as_set(&volume_filters);
        assert!(volume_labels.contains(&format!("{COMPOSE_PROJECT_LABEL}={TEST_PROJECT}")));
        assert!(!volume_labels.contains(&format!("{COMPOSE_PROJECT_LABEL}={inner_project}")));
        assert!(volume_labels.contains(&format!("{AMBER_COMPONENT_LABEL}={TEST_COMPONENT}")));
        assert!(volume_labels.contains(&format!("{AMBER_PROJECT_LABEL}={TEST_PROJECT}")));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn shutdown_cleanup_removes_owned_resources() {
        let docker = MockDocker::start().await;
        let state = State::new(DockerGatewayConfig {
            listen: "127.0.0.1:23750".parse().expect("valid listen addr"),
            docker_sock: docker.socket_path.clone(),
            compose_project: TEST_PROJECT.to_string(),
            callers: vec![default_caller()],
        });

        docker.enqueue_json(
            Method::GET,
            "/containers/json",
            StatusCode::OK,
            serde_json::json!([
                {"Id":"container-a"},
                {"Id":"container-b"},
            ]),
        );
        docker.enqueue_empty(
            Method::DELETE,
            "/containers/container-a",
            StatusCode::NO_CONTENT,
        );
        docker.enqueue_empty(
            Method::DELETE,
            "/containers/container-b",
            StatusCode::NO_CONTENT,
        );
        docker.enqueue_json(
            Method::GET,
            "/networks",
            StatusCode::OK,
            serde_json::json!([
                {"Id":"network-a"},
            ]),
        );
        docker.enqueue_empty(
            Method::DELETE,
            "/networks/network-a",
            StatusCode::NO_CONTENT,
        );
        docker.enqueue_json(
            Method::GET,
            "/volumes",
            StatusCode::OK,
            serde_json::json!({
                "Volumes": [
                    {"Name":"volume-a"},
                ]
            }),
        );
        docker.enqueue_empty(Method::DELETE, "/volumes/volume-a", StatusCode::NO_CONTENT);

        state.cleanup_created_resources_inner().await;

        let requests = docker.requests();

        let container_list = requests
            .iter()
            .find(|req| req.method == Method::GET && req.path == "/containers/json")
            .expect("containers list request");
        assert!(
            container_list.path_and_query.contains("all=1"),
            "containers cleanup should request all containers"
        );
        let container_filters = decode_filters(container_list);
        let container_labels = labels_as_set(&container_filters);
        assert!(container_labels.contains(AMBER_COMPONENT_LABEL));
        assert!(container_labels.contains(&format!("{AMBER_PROJECT_LABEL}={TEST_PROJECT}")));

        let network_list = requests
            .iter()
            .find(|req| req.method == Method::GET && req.path == "/networks")
            .expect("networks list request");
        let network_filters = decode_filters(network_list);
        let network_labels = labels_as_set(&network_filters);
        assert!(network_labels.contains(AMBER_COMPONENT_LABEL));
        assert!(network_labels.contains(&format!("{AMBER_PROJECT_LABEL}={TEST_PROJECT}")));

        let volume_list = requests
            .iter()
            .find(|req| req.method == Method::GET && req.path == "/volumes")
            .expect("volumes list request");
        let volume_filters = decode_filters(volume_list);
        let volume_labels = labels_as_set(&volume_filters);
        assert!(volume_labels.contains(AMBER_COMPONENT_LABEL));
        assert!(volume_labels.contains(&format!("{AMBER_PROJECT_LABEL}={TEST_PROJECT}")));

        let deleted_containers: HashSet<&str> = requests
            .iter()
            .filter(|req| req.method == Method::DELETE && req.path.starts_with("/containers/"))
            .map(|req| req.path.as_str())
            .collect();
        assert!(deleted_containers.contains("/containers/container-a"));
        assert!(deleted_containers.contains("/containers/container-b"));

        assert!(
            requests
                .iter()
                .any(|req| req.method == Method::DELETE && req.path == "/networks/network-a")
        );
        assert!(
            requests
                .iter()
                .any(|req| req.method == Method::DELETE && req.path == "/volumes/volume-a")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn versioned_paths_preserve_version_for_authorization_and_forwarding() {
        let gateway = GatewayHarness::start(vec![default_caller()]).await;
        gateway.enqueue_json(
            Method::GET,
            "/v1.41/containers/workload/json",
            StatusCode::OK,
            container_labels(TEST_COMPONENT, TEST_PROJECT),
        );
        gateway.enqueue_empty(
            Method::POST,
            "/v1.41/containers/workload/start",
            StatusCode::NO_CONTENT,
        );

        let response = send_gateway_request(
            gateway.addr,
            Method::POST,
            "/v1.41/containers/workload/start",
            &[],
            &[],
        )
        .await;
        assert_eq!(response.status, StatusCode::NO_CONTENT);

        let requests = gateway.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].path, "/v1.41/containers/workload/json");
        assert_eq!(requests[1].path, "/v1.41/containers/workload/start");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn exec_start_uses_cached_exec_to_container_mapping() {
        let gateway = GatewayHarness::start(vec![default_caller()]).await;
        gateway.enqueue_json(
            Method::GET,
            "/containers/workload/json",
            StatusCode::OK,
            container_labels(TEST_COMPONENT, TEST_PROJECT),
        );
        gateway.enqueue_json(
            Method::POST,
            "/containers/workload/exec",
            StatusCode::CREATED,
            serde_json::json!({"Id":"exec-1"}),
        );
        gateway.enqueue_json(
            Method::GET,
            "/containers/workload/json",
            StatusCode::OK,
            container_labels(TEST_COMPONENT, TEST_PROJECT),
        );
        gateway.enqueue_json(
            Method::POST,
            "/exec/exec-1/start",
            StatusCode::OK,
            serde_json::json!({"ok":true}),
        );

        let create_exec = send_gateway_request(
            gateway.addr,
            Method::POST,
            "/containers/workload/exec",
            &[("content-type", "application/json")],
            br#"{"Cmd":["echo","hi"]}"#,
        )
        .await;
        assert_eq!(create_exec.status, StatusCode::CREATED);

        let start_exec = send_gateway_request(
            gateway.addr,
            Method::POST,
            "/exec/exec-1/start",
            &[("content-type", "application/json")],
            br#"{"Detach":false}"#,
        )
        .await;
        assert_eq!(start_exec.status, StatusCode::OK);

        let requests = gateway.requests();
        let paths: HashSet<&str> = requests.iter().map(|req| req.path.as_str()).collect();
        assert!(paths.contains("/containers/workload/json"));
        assert!(paths.contains("/containers/workload/exec"));
        assert!(paths.contains("/exec/exec-1/start"));
        assert!(!paths.contains("/exec/exec-1/json"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn exec_start_falls_back_to_exec_inspect_when_cache_is_missing() {
        let gateway = GatewayHarness::start(vec![default_caller()]).await;
        gateway.enqueue_json(
            Method::GET,
            "/exec/exec-2/json",
            StatusCode::OK,
            serde_json::json!({"ContainerID":"workload"}),
        );
        gateway.enqueue_json(
            Method::GET,
            "/containers/workload/json",
            StatusCode::OK,
            container_labels(TEST_COMPONENT, TEST_PROJECT),
        );
        gateway.enqueue_json(
            Method::POST,
            "/exec/exec-2/start",
            StatusCode::OK,
            serde_json::json!({"ok":true}),
        );

        let response = send_gateway_request(
            gateway.addr,
            Method::POST,
            "/exec/exec-2/start",
            &[("content-type", "application/json")],
            br#"{"Detach":false}"#,
        )
        .await;
        assert_eq!(response.status, StatusCode::OK);

        let requests = gateway.requests();
        let paths: Vec<&str> = requests.iter().map(|req| req.path.as_str()).collect();
        assert!(paths.contains(&"/exec/exec-2/json"));
        assert!(paths.contains(&"/containers/workload/json"));
        assert!(paths.contains(&"/exec/exec-2/start"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn exec_start_denies_access_when_exec_belongs_to_foreign_container() {
        let gateway = GatewayHarness::start(vec![default_caller()]).await;
        gateway.enqueue_json(
            Method::GET,
            "/exec/exec-9/json",
            StatusCode::OK,
            serde_json::json!({"ContainerID":"foreign"}),
        );
        gateway.enqueue_json(
            Method::GET,
            "/containers/foreign/json",
            StatusCode::OK,
            container_labels("other-component", TEST_PROJECT),
        );

        let response = send_gateway_request(
            gateway.addr,
            Method::POST,
            "/exec/exec-9/start",
            &[("content-type", "application/json")],
            br#"{"Detach":false}"#,
        )
        .await;
        assert_eq!(response.status, StatusCode::FORBIDDEN);
        assert!(response_message(&response.body).contains("not authorized for this container"));

        let requests = gateway.requests();
        let paths: HashSet<&str> = requests.iter().map(|req| req.path.as_str()).collect();
        assert!(paths.contains("/exec/exec-9/json"));
        assert!(paths.contains("/containers/foreign/json"));
        assert!(!paths.contains("/exec/exec-9/start"));
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires a reachable Docker daemon via DOCKER_HOST, ~/.docker/run/docker.sock, or \
                /var/run/docker.sock"]
    async fn docker_daemon_e2e_enforces_scoping_and_policy() {
        let Some(docker_sock) = docker_socket_for_ignored_e2e() else {
            eprintln!("skipping docker daemon e2e: no docker unix socket found");
            return;
        };

        if UnixStream::connect(&docker_sock).await.is_err() {
            eprintln!(
                "skipping docker daemon e2e: docker socket exists but is not reachable at {}",
                docker_sock.display()
            );
            return;
        }

        let ping = send_docker_request(&docker_sock, Method::GET, "/_ping", None).await;
        if ping.status != StatusCode::OK {
            eprintln!(
                "skipping docker daemon e2e: /_ping returned {} with body {}",
                ping.status,
                String::from_utf8_lossy(&ping.body)
            );
            return;
        }

        let suffix = unique_test_suffix();
        let compose_project = format!("amber-gw-e2e-project-{suffix}");
        let component = format!("amber-gw-e2e-component-{suffix}");
        let foreign_component = format!("amber-gw-e2e-foreign-{suffix}");
        let owned_network = format!("amber-gw-owned-net-{suffix}");
        let foreign_network = format!("amber-gw-foreign-net-{suffix}");
        let owned_volume = format!("amber-gw-owned-vol-{suffix}");
        let foreign_volume = format!("amber-gw-foreign-vol-{suffix}");

        let listen = reserve_loopback_socket_addr();
        let config = DockerGatewayConfig {
            listen,
            docker_sock: docker_sock.clone(),
            compose_project: compose_project.clone(),
            callers: vec![CallerConfig {
                host: "127.0.0.1".to_string(),
                port: None,
                component: component.clone(),
                compose_service: component.clone(),
            }],
        };

        let gateway_task = tokio::spawn(async move {
            if let Err(err) = run(config).await {
                panic!("gateway run failed in e2e test: {err}");
            }
        });
        wait_until_gateway_listens(listen, &gateway_task).await;

        send_docker_request(
            &docker_sock,
            Method::POST,
            "/networks/create",
            Some(serde_json::json!({
                "Name": foreign_network.as_str(),
                "Labels": {
                    AMBER_PROJECT_LABEL: compose_project.as_str(),
                    AMBER_COMPONENT_LABEL: foreign_component.as_str()
                }
            })),
        )
        .await;

        send_docker_request(
            &docker_sock,
            Method::POST,
            "/volumes/create",
            Some(serde_json::json!({
                "Name": foreign_volume.as_str(),
                "Labels": {
                    AMBER_PROJECT_LABEL: compose_project.as_str(),
                    AMBER_COMPONENT_LABEL: foreign_component.as_str()
                }
            })),
        )
        .await;

        let create_network = send_gateway_request(
            listen,
            Method::POST,
            "/networks/create",
            &[("content-type", "application/json")],
            serde_json::json!({
                "Name": owned_network.as_str(),
                "Labels": {
                    AMBER_COMPONENT_LABEL: "attacker",
                    AMBER_PROJECT_LABEL: "attacker-project",
                    "user.label": "kept"
                }
            })
            .to_string()
            .as_bytes(),
        )
        .await;
        assert_eq!(
            create_network.status,
            StatusCode::CREATED,
            "network create failed via gateway: {}",
            String::from_utf8_lossy(&create_network.body)
        );

        let create_volume = send_gateway_request(
            listen,
            Method::POST,
            "/volumes/create",
            &[("content-type", "application/json")],
            serde_json::json!({
                "Name": owned_volume.as_str(),
                "Labels": {
                    AMBER_COMPONENT_LABEL: "attacker",
                    AMBER_PROJECT_LABEL: "attacker-project"
                }
            })
            .to_string()
            .as_bytes(),
        )
        .await;
        assert_eq!(
            create_volume.status,
            StatusCode::CREATED,
            "volume create failed via gateway: {}",
            String::from_utf8_lossy(&create_volume.body)
        );

        let owned_network_meta = send_docker_request(
            &docker_sock,
            Method::GET,
            &format!("/networks/{owned_network}"),
            None,
        )
        .await;
        assert_eq!(owned_network_meta.status, StatusCode::OK);
        let owned_network_value: serde_json::Value =
            serde_json::from_slice(&owned_network_meta.body).expect("owned network inspect json");
        let owned_network_labels = owned_network_value
            .get("Labels")
            .and_then(|value| value.as_object())
            .expect("owned network labels");
        assert_eq!(
            owned_network_labels
                .get(AMBER_COMPONENT_LABEL)
                .and_then(|value| value.as_str()),
            Some(component.as_str())
        );
        assert_eq!(
            owned_network_labels
                .get(AMBER_PROJECT_LABEL)
                .and_then(|value| value.as_str()),
            Some(compose_project.as_str())
        );
        assert_eq!(
            owned_network_labels
                .get("user.label")
                .and_then(|value| value.as_str()),
            Some("kept")
        );

        let owned_volume_meta = send_docker_request(
            &docker_sock,
            Method::GET,
            &format!("/volumes/{owned_volume}"),
            None,
        )
        .await;
        assert_eq!(owned_volume_meta.status, StatusCode::OK);
        let owned_volume_value: serde_json::Value =
            serde_json::from_slice(&owned_volume_meta.body).expect("owned volume inspect json");
        let owned_volume_labels = owned_volume_value
            .get("Labels")
            .and_then(|value| value.as_object())
            .expect("owned volume labels");
        assert_eq!(
            owned_volume_labels
                .get(AMBER_COMPONENT_LABEL)
                .and_then(|value| value.as_str()),
            Some(component.as_str())
        );
        assert_eq!(
            owned_volume_labels
                .get(AMBER_PROJECT_LABEL)
                .and_then(|value| value.as_str()),
            Some(compose_project.as_str())
        );

        let deny_network = send_gateway_request(
            listen,
            Method::GET,
            &format!("/networks/{foreign_network}"),
            &[],
            &[],
        )
        .await;
        assert_eq!(deny_network.status, StatusCode::FORBIDDEN);

        let deny_volume = send_gateway_request(
            listen,
            Method::GET,
            &format!("/volumes/{foreign_volume}"),
            &[],
            &[],
        )
        .await;
        assert_eq!(deny_volume.status, StatusCode::FORBIDDEN);

        let list_networks = send_gateway_request(listen, Method::GET, "/networks", &[], &[]).await;
        assert_eq!(list_networks.status, StatusCode::OK);
        let networks_value: serde_json::Value =
            serde_json::from_slice(&list_networks.body).expect("list networks json");
        let network_names: HashSet<String> = networks_value
            .as_array()
            .expect("networks list array")
            .iter()
            .filter_map(|entry| {
                entry
                    .get("Name")
                    .and_then(|name| name.as_str())
                    .map(str::to_string)
            })
            .collect();
        assert!(network_names.contains(&owned_network));
        assert!(!network_names.contains(&foreign_network));

        let list_volumes = send_gateway_request(listen, Method::GET, "/volumes", &[], &[]).await;
        assert_eq!(list_volumes.status, StatusCode::OK);
        let volumes_value: serde_json::Value =
            serde_json::from_slice(&list_volumes.body).expect("list volumes json");
        let volume_names: HashSet<String> = volumes_value
            .get("Volumes")
            .and_then(|volumes| volumes.as_array())
            .map(|volumes| {
                volumes
                    .iter()
                    .filter_map(|entry| {
                        entry
                            .get("Name")
                            .and_then(|name| name.as_str())
                            .map(str::to_string)
                    })
                    .collect()
            })
            .unwrap_or_default();
        assert!(volume_names.contains(&owned_volume));
        assert!(!volume_names.contains(&foreign_volume));

        let blocked_connect = send_gateway_request(
            listen,
            Method::POST,
            &format!("/networks/{owned_network}/connect"),
            &[("content-type", "application/json")],
            br#"{"Container":"dummy"}"#,
        )
        .await;
        assert_eq!(blocked_connect.status, StatusCode::FORBIDDEN);

        gateway_task.abort();
        docker_delete_network_best_effort(&docker_sock, &owned_network).await;
        docker_delete_network_best_effort(&docker_sock, &foreign_network).await;
        docker_delete_volume_best_effort(&docker_sock, &owned_volume).await;
        docker_delete_volume_best_effort(&docker_sock, &foreign_volume).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires a reachable Docker daemon via DOCKER_HOST, ~/.docker/run/docker.sock, or \
                /var/run/docker.sock"]
    async fn docker_daemon_e2e_enforces_multicaller_container_exec_and_upgrade() {
        let Some(docker_sock) = docker_socket_for_ignored_e2e() else {
            eprintln!("skipping docker daemon e2e: no docker unix socket found");
            return;
        };

        if UnixStream::connect(&docker_sock).await.is_err() {
            eprintln!(
                "skipping docker daemon e2e: docker socket exists but is not reachable at {}",
                docker_sock.display()
            );
            return;
        }

        let ping = send_docker_request(&docker_sock, Method::GET, "/_ping", None).await;
        if ping.status != StatusCode::OK {
            eprintln!(
                "skipping docker daemon e2e: /_ping returned {} with body {}",
                ping.status,
                String::from_utf8_lossy(&ping.body)
            );
            return;
        }

        let Some(image) = docker_image_for_ignored_e2e(&docker_sock).await else {
            return;
        };

        let suffix = unique_test_suffix();
        let compose_project = format!("amber-gw-e2e-project-{suffix}");
        let component_a = format!("amber-gw-e2e-component-a-{suffix}");
        let component_b = format!("amber-gw-e2e-component-b-{suffix}");
        let owned_network_a = format!("amber-gw-owned-net-a-{suffix}");
        let owned_network_b = format!("amber-gw-owned-net-b-{suffix}");
        let owned_container_a = format!("amber-gw-owned-container-a-{suffix}");

        let (caller_a_socket, caller_a_port) = reserve_bound_loopback_socket();
        let (caller_b_socket, caller_b_port) = reserve_bound_loopback_socket();
        assert_ne!(caller_a_port, caller_b_port);

        let listen = reserve_loopback_socket_addr();
        let config = DockerGatewayConfig {
            listen,
            docker_sock: docker_sock.clone(),
            compose_project: compose_project.clone(),
            callers: vec![
                CallerConfig {
                    host: "127.0.0.1".to_string(),
                    port: Some(caller_a_port),
                    component: component_a.clone(),
                    compose_service: component_a.clone(),
                },
                CallerConfig {
                    host: "127.0.0.1".to_string(),
                    port: Some(caller_b_port),
                    component: component_b.clone(),
                    compose_service: component_b.clone(),
                },
            ],
        };

        let gateway_task = tokio::spawn(async move {
            if let Err(err) = run(config).await {
                panic!("gateway run failed in multicaller e2e test: {err}");
            }
        });
        wait_until_gateway_listens(listen, &gateway_task).await;

        let mut caller_a = GatewayClient::connect_from_socket(caller_a_socket, listen).await;
        let mut caller_b = GatewayClient::connect_from_socket(caller_b_socket, listen).await;

        let create_network_a = caller_a
            .request(
                Method::POST,
                "/networks/create",
                &[("content-type", "application/json")],
                serde_json::json!({
                    "Name": owned_network_a.as_str(),
                })
                .to_string()
                .as_bytes(),
            )
            .await;
        assert_eq!(
            create_network_a.status,
            StatusCode::CREATED,
            "network A create failed via gateway: {}",
            String::from_utf8_lossy(&create_network_a.body)
        );

        let create_network_b = caller_b
            .request(
                Method::POST,
                "/networks/create",
                &[("content-type", "application/json")],
                serde_json::json!({
                    "Name": owned_network_b.as_str(),
                })
                .to_string()
                .as_bytes(),
            )
            .await;
        assert_eq!(
            create_network_b.status,
            StatusCode::CREATED,
            "network B create failed via gateway: {}",
            String::from_utf8_lossy(&create_network_b.body)
        );

        let cross_network_a_denied = caller_b
            .request(
                Method::GET,
                &format!("/networks/{owned_network_a}"),
                &[],
                &[],
            )
            .await;
        assert_eq!(cross_network_a_denied.status, StatusCode::FORBIDDEN);

        let cross_network_b_denied = caller_a
            .request(
                Method::GET,
                &format!("/networks/{owned_network_b}"),
                &[],
                &[],
            )
            .await;
        assert_eq!(cross_network_b_denied.status, StatusCode::FORBIDDEN);

        let create_container_a = caller_a
            .request(
                Method::POST,
                &format!("/containers/create?name={owned_container_a}"),
                &[("content-type", "application/json")],
                serde_json::json!({
                    "Image": image.as_str(),
                    "Cmd": ["sleep", "60"],
                    "HostConfig": {
                        "NetworkMode": owned_network_a.as_str()
                    }
                })
                .to_string()
                .as_bytes(),
            )
            .await;
        assert_eq!(
            create_container_a.status,
            StatusCode::CREATED,
            "container create failed via gateway: {}",
            String::from_utf8_lossy(&create_container_a.body)
        );

        let start_container_a = caller_a
            .request(
                Method::POST,
                &format!("/containers/{owned_container_a}/start"),
                &[],
                &[],
            )
            .await;
        assert!(
            matches!(
                start_container_a.status,
                StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED
            ),
            "container start via gateway failed: {} body={}",
            start_container_a.status,
            String::from_utf8_lossy(&start_container_a.body)
        );

        let inspect_container_denied = caller_b
            .request(
                Method::GET,
                &format!("/containers/{owned_container_a}/json"),
                &[],
                &[],
            )
            .await;
        assert_eq!(inspect_container_denied.status, StatusCode::FORBIDDEN);

        let start_container_denied = caller_b
            .request(
                Method::POST,
                &format!("/containers/{owned_container_a}/start"),
                &[],
                &[],
            )
            .await;
        assert_eq!(start_container_denied.status, StatusCode::FORBIDDEN);

        let list_containers_a = caller_a
            .request(Method::GET, "/containers/json?all=1", &[], &[])
            .await;
        assert_eq!(list_containers_a.status, StatusCode::OK);
        let names_a = parse_container_names(&list_containers_a.body);
        assert!(names_a.contains(&owned_container_a));

        let list_containers_b = caller_b
            .request(Method::GET, "/containers/json?all=1", &[], &[])
            .await;
        assert_eq!(list_containers_b.status, StatusCode::OK);
        let names_b = parse_container_names(&list_containers_b.body);
        assert!(!names_b.contains(&owned_container_a));

        let create_exec_a = caller_a
            .request(
                Method::POST,
                &format!("/containers/{owned_container_a}/exec"),
                &[("content-type", "application/json")],
                serde_json::json!({
                    "Cmd": ["echo", "gateway-upgrade"],
                    "AttachStdout": true,
                    "AttachStderr": true
                })
                .to_string()
                .as_bytes(),
            )
            .await;
        assert_eq!(
            create_exec_a.status,
            StatusCode::CREATED,
            "exec create via gateway failed: {}",
            String::from_utf8_lossy(&create_exec_a.body)
        );
        let exec_id = response_json_id(&create_exec_a.body);

        let denied_exec_start = caller_b
            .request(
                Method::POST,
                &format!("/exec/{exec_id}/start"),
                &[("content-type", "application/json")],
                br#"{"Detach":false,"Tty":false}"#,
            )
            .await;
        assert_eq!(denied_exec_start.status, StatusCode::FORBIDDEN);

        let allowed_exec_start = caller_a
            .request_with_upgrade(
                Method::POST,
                &format!("/exec/{exec_id}/start"),
                &[
                    ("content-type", "application/json"),
                    ("connection", "Upgrade"),
                    ("upgrade", "tcp"),
                ],
                br#"{"Detach":false,"Tty":false}"#,
            )
            .await;
        assert!(
            matches!(
                allowed_exec_start.status,
                StatusCode::OK | StatusCode::SWITCHING_PROTOCOLS
            ),
            "exec start via gateway failed: {} body={}",
            allowed_exec_start.status,
            String::from_utf8_lossy(&allowed_exec_start.body)
        );
        assert!(
            String::from_utf8_lossy(&allowed_exec_start.body).contains("gateway-upgrade"),
            "exec output did not contain expected marker, body={}",
            String::from_utf8_lossy(&allowed_exec_start.body)
        );

        gateway_task.abort();
        docker_delete_container_best_effort(&docker_sock, &owned_container_a).await;
        docker_delete_network_best_effort(&docker_sock, &owned_network_a).await;
        docker_delete_network_best_effort(&docker_sock, &owned_network_b).await;
    }
}
