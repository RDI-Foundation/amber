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
                            Ok::<_, std::convert::Infallible>(handle_mock_request(req, state).await)
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
        let stream = socket
            .connect(addr)
            .await
            .unwrap_or_else(|err| panic!("connect from bound local source socket failed: {err}"));
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

async fn send_gateway_request_from_socket(
    socket: TcpSocket,
    source_port: u16,
    addr: SocketAddr,
    method: Method,
    target: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> GatewayResponse {
    let stream = socket
        .connect(addr)
        .await
        .unwrap_or_else(|err| panic!("connect from local source port {source_port} failed: {err}"));
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
    let query_map: HashMap<String, String> =
        serde_urlencoded::from_str(query).expect("query should decode");
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
            StatusCode::OK | StatusCode::NO_CONTENT | StatusCode::NOT_FOUND | StatusCode::CONFLICT
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
            StatusCode::OK | StatusCode::NO_CONTENT | StatusCode::NOT_FOUND | StatusCode::CONFLICT
        ),
        "unexpected container delete status for {name}: {} body={}",
        response.status,
        String::from_utf8_lossy(&response.body)
    );
}

mod compose;
mod e2e;
mod gateway;
mod unit;
