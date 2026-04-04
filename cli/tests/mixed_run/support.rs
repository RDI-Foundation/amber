#![cfg(any(target_os = "macos", target_os = "linux"))]

#[path = "../test_support/cloud_image.rs"]
mod cloud_image_support;
#[path = "../test_support/outputs_root.rs"]
mod outputs_root_support;
#[path = "../test_support/target_dir.rs"]
mod target_dir_support;
#[path = "../test_support/workspace_root.rs"]
mod workspace_root_support;

use std::{
    collections::BTreeSet,
    env, fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use amber_images::{AMBER_HELPER, AMBER_PROVISIONER, AMBER_ROUTER};
use cloud_image_support::default_host_arch_cloud_image_filename;
use outputs_root_support::cli_test_outputs_root;
use serde_json::{Value, json};
use target_dir_support::cargo_target_dir;
pub(crate) use workspace_root_support::workspace_root;

const COMMON_HTTP_APP: &str = r#"import json
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from urllib.request import Request, urlopen

NAME = os.environ["NAME"]
PORT = int(os.environ.get("PORT", "8080"))
UPSTREAMS = {
    key.removeprefix("UPSTREAM_").lower(): value.rstrip("/")
    for key, value in os.environ.items()
    if key.startswith("UPSTREAM_") and value
}
ADVERSARIAL_HOST_URL = os.environ.get("ADVERSARIAL_HOST_URL", "").rstrip("/")

def fetch_text(url: str, timeout: float = 10.0) -> str:
    request = Request(url, headers={"Connection": "close"})
    with urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8")

def fetch_host_probe(url: str, timeout: float = 1.0) -> str:
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise ValueError("missing host")
    port = parsed.port or 80
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("utf-8")
        sock.sendall(request)
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    _, _, body = b"".join(chunks).decode("utf-8", errors="replace").partition("\r\n\r\n")
    return body

def send(handler: BaseHTTPRequestHandler, status: int, body: str) -> None:
    payload = body.encode("utf-8")
    handler.send_response(status)
    handler.send_header("content-type", "text/plain; charset=utf-8")
    handler.send_header("content-length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/id":
            send(self, 200, NAME)
            return
        if self.path == "/upstreams":
            send(self, 200, json.dumps(sorted(UPSTREAMS)))
            return
        if self.path.startswith("/call/"):
            alias = self.path.removeprefix("/call/")
            upstream = UPSTREAMS.get(alias)
            if not upstream:
                send(self, 404, f"missing upstream {alias}")
                return
            send(self, 200, fetch_text(f"{upstream}/id"))
            return
        if self.path == "/adversarial-host":
            if not ADVERSARIAL_HOST_URL:
                send(self, 404, "missing adversarial host URL")
                return
            try:
                send(self, 200, fetch_host_probe(ADVERSARIAL_HOST_URL, timeout=1.0))
            except Exception as err:
                send(self, 200, f"blocked:{err.__class__.__name__}")
            return
        if self.path == "/crash":
            def crash() -> None:
                os._exit(42)

            threading.Thread(target=crash, daemon=True).start()
            send(self, 202, "crashing")
            return
        send(self, 200, "ok")

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[{NAME}] {fmt % args}", flush=True)

ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
"#;

pub(crate) const TEST_APP_IMAGE: &str = "python:3.13-alpine";

pub(crate) fn outputs_root() -> PathBuf {
    cli_test_outputs_root(&workspace_root())
}

pub(crate) struct TestTempDir {
    path: PathBuf,
    _guard: Option<tempfile::TempDir>,
}

pub(crate) struct SpawnedProxy {
    child: std::process::Child,
    log_path: PathBuf,
    output_dir: PathBuf,
}

impl TestTempDir {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

pub(crate) fn runtime_bin_dir() -> &'static PathBuf {
    static BIN_DIR: OnceLock<PathBuf> = OnceLock::new();
    BIN_DIR.get_or_init(|| {
        let output = Command::new("cargo")
            .current_dir(workspace_root())
            .arg("build")
            .arg("-q")
            .arg("-p")
            .arg("amber-cli")
            .arg("-p")
            .arg("amber-router")
            .arg("-p")
            .arg("amber-helper")
            .output()
            .expect("failed to build amber runtime binaries");
        assert!(
            output.status.success(),
            "failed to build runtime binaries\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        cargo_target_dir(&workspace_root()).join("debug")
    })
}

pub(crate) fn mixed_run_base_image() -> PathBuf {
    env::var_os("AMBER_MIXED_RUN_BASE_IMAGE")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root().join(default_host_arch_cloud_image_filename()))
}

pub(crate) fn temp_output_dir(prefix: &str) -> TestTempDir {
    fs::create_dir_all(outputs_root()).expect("failed to create cli test outputs root");
    let temp = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(outputs_root())
        .expect("failed to create temporary test directory");
    if env::var_os("AMBER_TEST_KEEP_OUTPUTS").is_some() {
        let path = temp.keep();
        eprintln!("preserving mixed-run test outputs in {}", path.display());
        return TestTempDir { path, _guard: None };
    }
    let path = temp.path().to_path_buf();
    TestTempDir {
        path,
        _guard: Some(temp),
    }
}

pub(crate) fn pick_free_port() -> u16 {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    listener.local_addr().unwrap().port()
}

pub(crate) fn docker_host_ip() -> String {
    let mut cmd = Command::new("docker");
    cmd.arg("run").arg("--rm");
    #[cfg(target_os = "linux")]
    {
        cmd.arg("--add-host")
            .arg("host.docker.internal:host-gateway");
    }
    let output = cmd
        .arg(TEST_APP_IMAGE)
        .arg("python3")
        .arg("-c")
        .arg("import socket; print(socket.gethostbyname('host.docker.internal'))")
        .output()
        .expect("failed to resolve Docker host IP");
    assert!(
        output.status.success(),
        "failed to resolve Docker host IP\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

pub(crate) fn ensure_local_image(tag: &str) {
    let inspect = Command::new("docker")
        .arg("image")
        .arg("inspect")
        .arg(tag)
        .status()
        .unwrap_or_else(|err| panic!("failed to inspect docker image {tag}: {err}"));
    if inspect.success() {
        return;
    }
    let status = Command::new("docker")
        .arg("pull")
        .arg(tag)
        .status()
        .unwrap_or_else(|err| panic!("failed to pull docker image {tag}: {err}"));
    assert!(status.success(), "docker pull failed for {tag}");
}

pub(crate) fn docker_host_http_url(port: u16) -> String {
    format!("http://{}:{port}/", docker_host_ip())
}

pub(crate) fn write_json(path: &Path, value: &Value) {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).expect("test fixture should serialize"),
    )
    .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));
}

pub(crate) fn read_json(path: &Path) -> Value {
    serde_json::from_slice(
        &fs::read(path).unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display())),
    )
    .unwrap_or_else(|err| panic!("invalid JSON {}: {err}", path.display()))
}

pub(crate) fn http_get(port: u16, path: &str) -> Option<(u16, String)> {
    http_request_with_timeout("GET", port, path, None, Duration::from_secs(5))
}

pub(crate) fn http_get_with_timeout(
    port: u16,
    path: &str,
    timeout: Duration,
) -> Option<(u16, String)> {
    http_request_with_timeout("GET", port, path, None, timeout)
}

pub(crate) fn http_request_with_timeout(
    method: &str,
    port: u16,
    path: &str,
    body: Option<&str>,
    timeout: Duration,
) -> Option<(u16, String)> {
    let mut command = Command::new("curl");
    command
        .arg("-sS")
        .arg("--max-time")
        .arg(format!("{:.3}", timeout.as_secs_f64()))
        .arg("-X")
        .arg(method);
    if let Some(body) = body {
        command
            .arg("-H")
            .arg("content-type: application/json")
            .arg("--data")
            .arg(body);
    }
    let output = command
        .arg("-o")
        .arg("-")
        .arg("-w")
        .arg("\n%{http_code}")
        .arg(format!("http://127.0.0.1:{port}{path}"))
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let (body, status) = stdout.rsplit_once('\n')?;
    Some((status.trim().parse().ok()?, body.trim().to_string()))
}

pub(crate) fn wait_for_body(
    proxy: &mut SpawnedProxy,
    port: u16,
    path: &str,
    timeout: Duration,
) -> String {
    let deadline = Instant::now() + timeout;
    let mut last_response = None;
    while Instant::now() < deadline {
        if let Some((status, body)) = http_get(port, path) {
            if status == 200 {
                return body;
            }
            last_response = Some((status, body));
        }
        if let Ok(Some(status)) = proxy.child.try_wait() {
            panic!(
                "amber proxy exited before http://127.0.0.1:{port}{path} became ready\nstatus: \
                 {status}\noutput dir: {}\nlog ({}):\n{}",
                proxy.output_dir.display(),
                proxy.log_path.display(),
                fs::read_to_string(&proxy.log_path).unwrap_or_default()
            );
        }
        thread::sleep(Duration::from_millis(250));
    }
    let last_response = last_response
        .map(|(status, body)| format!("last http response: {status}\n{body}\n"))
        .unwrap_or_else(|| "last http response: <none>\n".to_string());
    panic!(
        "timed out waiting for http://127.0.0.1:{port}{path}\noutput dir: {}\n{last_response}log \
         ({}):\n{}",
        proxy.output_dir.display(),
        proxy.log_path.display(),
        fs::read_to_string(&proxy.log_path).unwrap_or_default()
    );
}

pub(crate) fn wait_for_path(proxy: &mut SpawnedProxy, port: u16, path: &str, timeout: Duration) {
    let _ = wait_for_body(proxy, port, path, timeout);
}

pub(crate) fn wait_for_condition(
    timeout: Duration,
    mut predicate: impl FnMut() -> bool,
    label: &str,
) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if predicate() {
            return;
        }
        thread::sleep(Duration::from_millis(250));
    }
    panic!("timed out waiting for {label}");
}

pub(crate) fn wait_for_file(path: &Path, timeout: Duration) {
    wait_for_condition(
        timeout,
        || path.is_file(),
        &format!("file {}", path.display()),
    );
}

pub(crate) fn wait_for_single_run_root(storage_root: &Path, timeout: Duration) -> PathBuf {
    let runs_dir = storage_root.join("runs");
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let mut runs = collect_run_roots(storage_root);
        if runs.len() == 1 {
            return runs.pop().expect("single run should exist");
        }
        thread::sleep(Duration::from_millis(250));
    }
    panic!(
        "timed out waiting for single run root under {}",
        runs_dir.display()
    );
}

fn collect_run_roots(storage_root: &Path) -> Vec<PathBuf> {
    let mut runs = fs::read_dir(storage_root.join("runs"))
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    runs.sort();
    runs
}

pub(crate) fn wait_for_state_pid_change(
    run_root: &Path,
    site_id: &str,
    field: &str,
    old_pid: u32,
    timeout: Duration,
) -> Value {
    let state_path = run_root
        .join("state")
        .join(site_id)
        .join("manager-state.json");
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if state_path.is_file() {
            let state = read_json(&state_path);
            if let Some(pid) = state[field].as_u64()
                && pid as u32 != old_pid
            {
                return state;
            }
        }
        thread::sleep(Duration::from_millis(250));
    }
    panic!(
        "timed out waiting for site {site_id} field {field} to change from {old_pid}\nlast \
         state:\n{}",
        if state_path.is_file() {
            fs::read_to_string(&state_path).unwrap_or_default()
        } else {
            String::from("<missing>")
        }
    );
}

pub(crate) fn wait_for_text(path: &Path, needle: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let contents = fs::read_to_string(path).unwrap_or_default();
        if contents.contains(needle) {
            return contents;
        }
        thread::sleep(Duration::from_millis(250));
    }
    panic!(
        "timed out waiting for `{needle}` in {}\nlast contents:\n{}",
        path.display(),
        fs::read_to_string(path).unwrap_or_default()
    );
}

pub(crate) fn append_debug_file(out: &mut String, label: &str, path: &Path) {
    if !path.is_file() {
        return;
    }
    out.push_str(&format!(
        "\n{label} ({}):\n{}",
        path.display(),
        fs::read_to_string(path).unwrap_or_default()
    ));
}

pub(crate) fn site_debug_context(run_root: &Path, site_id: &str) -> String {
    let state_root = run_root.join("state").join(site_id);
    let mut out = String::new();
    append_debug_file(
        &mut out,
        "manager state",
        &state_root.join("manager-state.json"),
    );
    append_debug_file(
        &mut out,
        "supervisor log",
        &state_root.join("supervisor.log"),
    );
    append_debug_file(
        &mut out,
        "port-forward log",
        &state_root.join("port-forward.log"),
    );
    append_debug_file(&mut out, "site log", &state_root.join("site.log"));
    out
}

pub(crate) fn run_debug_context(run_root: &Path) -> String {
    let state_root = run_root.join("state");
    let Ok(entries) = fs::read_dir(&state_root) else {
        return String::new();
    };
    let mut site_ids = entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            entry
                .file_type()
                .ok()
                .filter(|kind| kind.is_dir())
                .and_then(|_| entry.file_name().into_string().ok())
        })
        .collect::<Vec<_>>();
    site_ids.sort();
    site_ids
        .into_iter()
        .map(|site_id| {
            format!(
                "\n== site {site_id} =={}",
                site_debug_context(run_root, &site_id)
            )
        })
        .collect()
}

pub(crate) fn spawn_proxy(
    output_dir: &Path,
    export: &str,
    local_port: u16,
    extra_args: &[String],
) -> SpawnedProxy {
    spawn_proxy_with_exports(output_dir, &[(export, local_port)], extra_args)
}

pub(crate) fn spawn_proxy_target(
    target: &str,
    export: &str,
    local_port: u16,
    extra_args: &[String],
) -> SpawnedProxy {
    spawn_proxy_target_with_exports(target, &[(export, local_port)], extra_args)
}

pub(crate) fn spawn_proxy_with_exports(
    output_dir: &Path,
    exports: &[(&str, u16)],
    extra_args: &[String],
) -> SpawnedProxy {
    let target = output_dir.display().to_string();
    spawn_proxy_target_with_exports(&target, exports, extra_args)
}

pub(crate) fn spawn_proxy_target_with_exports(
    target: &str,
    exports: &[(&str, u16)],
    extra_args: &[String],
) -> SpawnedProxy {
    fs::create_dir_all(outputs_root()).expect("failed to create cli test outputs root");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be available")
        .as_nanos();
    let log_path = outputs_root().join(format!(
        "mixed-run-proxy-{}-{nonce}.log",
        std::process::id()
    ));
    let log = fs::File::create(&log_path).expect("failed to create amber proxy log");
    let log_err = log
        .try_clone()
        .expect("failed to clone amber proxy log handle");
    let mut cmd = amber_command();
    cmd.arg("proxy").arg(target);
    for (export, local_port) in exports {
        cmd.arg("--export")
            .arg(format!("{export}=127.0.0.1:{local_port}"));
    }
    let child = cmd
        .args(extra_args)
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()
        .expect("failed to start amber proxy");
    SpawnedProxy {
        child,
        log_path,
        output_dir: PathBuf::from(target),
    }
}

pub(crate) fn stop_proxy(proxy: &mut SpawnedProxy) {
    stop_child(&mut proxy.child);
}

pub(crate) fn stop_child(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

pub(crate) fn amber_command() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_amber"));
    cmd.env("AMBER_RUNTIME_BIN_DIR", runtime_bin_dir());
    if let Some(kubeconfig) = env::var_os("AMBER_TEST_KIND_KUBECONFIG") {
        cmd.env("KUBECONFIG", kubeconfig);
    }
    cmd
}

pub(crate) fn use_prebuilt_images() -> bool {
    env::var_os("AMBER_TEST_USE_PREBUILT_IMAGES").is_some()
}

pub(crate) fn image_platform_opt(tag: &str) -> Option<String> {
    let output = Command::new("docker")
        .arg("image")
        .arg("inspect")
        .arg("-f")
        .arg("{{.Architecture}}")
        .arg(tag)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let arch = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if arch.is_empty() {
        return None;
    }
    Some(format!("linux/{arch}"))
}

pub(crate) fn ensure_docker_image(tag: &str, dockerfile: &Path) {
    if use_prebuilt_images() {
        image_platform_opt(tag).unwrap_or_else(|| {
            panic!(
                "AMBER_TEST_USE_PREBUILT_IMAGES is set but {tag} is not available locally. Ensure \
                 the image is pulled and retagged before running mixed-run tests."
            )
        });
        return;
    }

    let mut command = Command::new("docker");
    if docker_supports_buildx() {
        command.arg("buildx").arg("build").arg("--load");
    } else {
        command.env("DOCKER_BUILDKIT", "1");
        command.arg("build");
    }
    let status = command
        .arg("-t")
        .arg(tag)
        .arg("-f")
        .arg(dockerfile)
        .arg(workspace_root())
        .status()
        .unwrap_or_else(|err| panic!("failed to build {tag}: {err}"));
    assert!(status.success(), "docker build failed for {tag}");
}

pub(crate) fn docker_supports_buildx() -> bool {
    static READY: OnceLock<bool> = OnceLock::new();
    *READY.get_or_init(|| {
        Command::new("docker")
            .arg("buildx")
            .arg("version")
            .status()
            .is_ok_and(|status| status.success())
    })
}

pub(crate) fn ensure_internal_images() {
    static READY: OnceLock<()> = OnceLock::new();
    READY.get_or_init(|| {
        let root = workspace_root();
        ensure_local_image(TEST_APP_IMAGE);
        ensure_docker_image(
            AMBER_ROUTER.reference,
            &root.join("docker/amber-router/Dockerfile"),
        );
        ensure_docker_image(
            AMBER_PROVISIONER.reference,
            &root.join("docker/amber-provisioner/Dockerfile"),
        );
        ensure_docker_image(
            AMBER_HELPER.reference,
            &root.join("docker/amber-helper/Dockerfile"),
        );
    });
}

pub(crate) fn load_kind_image(cluster_name: &str, image: &str) {
    let status = Command::new("kind")
        .arg("load")
        .arg("docker-image")
        .arg("--name")
        .arg(cluster_name)
        .arg(image)
        .status()
        .unwrap_or_else(|err| {
            panic!("failed to load {image} into kind cluster {cluster_name}: {err}")
        });
    assert!(
        status.success(),
        "kind load docker-image failed for {image} in cluster {cluster_name}"
    );
}

pub(crate) fn ensure_kind_internal_images(kind_cluster: &KindCluster) {
    ensure_internal_images();
    static READY: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
    let name = kind_cluster.name.clone();
    let loaded = READY.get_or_init(|| Mutex::new(BTreeSet::new()));
    {
        let loaded = loaded.lock().expect("kind image-load guard should lock");
        if loaded.contains(&name) {
            return;
        }
    }
    load_kind_image(&name, AMBER_ROUTER.reference);
    load_kind_image(&name, AMBER_PROVISIONER.reference);
    load_kind_image(&name, AMBER_HELPER.reference);
    load_kind_image(&name, TEST_APP_IMAGE);
    loaded
        .lock()
        .expect("kind image-load guard should lock")
        .insert(name);
}

pub(crate) fn kill_pid(pid: u32) {
    #[cfg(unix)]
    unsafe {
        let _ = libc::kill(pid as i32, libc::SIGTERM);
    }
}

pub(crate) fn pid_is_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let alive = unsafe {
            libc::kill(pid as i32, 0) == 0
                || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
        };
        alive && process_status_code(pid) != Some('Z')
    }

    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

#[cfg(unix)]
pub(crate) fn process_status_code(pid: u32) -> Option<char> {
    let output = Command::new("ps")
        .arg("-o")
        .arg("stat=")
        .arg("-p")
        .arg(pid.to_string())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    output
        .stdout
        .split(|byte| byte.is_ascii_whitespace())
        .find(|field| !field.is_empty())
        .and_then(|field| field.first().copied())
        .map(|state| (state as char).to_ascii_uppercase())
}

#[derive(Debug)]
pub(crate) struct RunHandle {
    pub(crate) run_id: String,
    pub(crate) run_root: PathBuf,
    pub(crate) receipt: Value,
    storage_root: PathBuf,
    command_env: Vec<(String, String)>,
    stopped: bool,
}

pub(crate) struct FailedRun {
    pub(crate) output: std::process::Output,
    pub(crate) run_root: PathBuf,
}

impl RunHandle {
    pub(crate) fn site_artifact_dir(&self, site_id: &str) -> PathBuf {
        PathBuf::from(
            self.receipt["sites"][site_id]["artifact_dir"]
                .as_str()
                .unwrap_or_else(|| panic!("missing artifact_dir for site {site_id}")),
        )
    }

    pub(crate) fn stop(&mut self) {
        if self.stopped {
            return;
        }
        let output = amber_command()
            .arg("stop")
            .arg(&self.run_id)
            .arg("--storage-root")
            .arg(&self.storage_root)
            .envs(self.command_env.iter().map(|(key, value)| (key, value)))
            .output()
            .expect("failed to run amber stop");
        assert!(
            output.status.success(),
            "amber stop failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        self.stopped = true;
    }
}

impl Drop for RunHandle {
    fn drop(&mut self) {
        if self.stopped {
            return;
        }
        let _ = amber_command()
            .arg("stop")
            .arg(&self.run_id)
            .arg("--storage-root")
            .arg(&self.storage_root)
            .envs(self.command_env.iter().map(|(key, value)| (key, value)))
            .output();
        self.stopped = true;
    }
}

pub(crate) fn parse_run_id(stdout: &[u8]) -> String {
    String::from_utf8_lossy(stdout)
        .lines()
        .find_map(|line| line.strip_prefix("run_id="))
        .expect("amber run should print run_id")
        .to_string()
}

pub(crate) fn wait_for_receipt(storage_root: &Path, run_id: &str, timeout: Duration) -> Value {
    let receipt_path = storage_root.join("runs").join(run_id).join("receipt.json");
    wait_for_file(&receipt_path, timeout);
    read_json(&receipt_path)
}

pub(crate) fn run_manifest_with_args(
    manifest: &Path,
    placement: &Path,
    storage_root: &Path,
    extra_args: &[&str],
) -> RunHandle {
    run_manifest_with_args_and_env(manifest, placement, storage_root, extra_args, &[])
}

pub(crate) fn run_manifest_with_args_and_env(
    manifest: &Path,
    placement: &Path,
    storage_root: &Path,
    extra_args: &[&str],
    extra_env: &[(&str, &str)],
) -> RunHandle {
    let output = amber_command()
        .arg("run")
        .arg(manifest)
        .arg("--placement")
        .arg(placement)
        .arg("--storage-root")
        .arg(storage_root)
        .args(extra_args)
        .envs(extra_env.iter().copied())
        .output()
        .expect("failed to run amber run");
    assert!(
        output.status.success(),
        "amber run failed\nstdout:\n{}\nstderr:\n{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        collect_run_roots(storage_root)
            .into_iter()
            .next()
            .map(|run_root| format!(
                "\nrun root: {}{}",
                run_root.display(),
                run_debug_context(&run_root)
            ))
            .unwrap_or_default(),
    );
    let run_root = wait_for_single_run_root(storage_root, Duration::from_secs(60));
    let run_id = parse_run_id(&output.stdout);
    let expected_run_root = storage_root.join("runs").join(&run_id);
    assert_eq!(run_root, expected_run_root);
    let receipt = wait_for_receipt(storage_root, &run_id, Duration::from_secs(240));
    RunHandle {
        run_id,
        run_root,
        receipt,
        storage_root: storage_root.to_path_buf(),
        command_env: extra_env
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect(),
        stopped: false,
    }
}

pub(crate) fn run_manifest(manifest: &Path, placement: &Path, storage_root: &Path) -> RunHandle {
    run_manifest_with_args(manifest, placement, storage_root, &[])
}

pub(crate) fn run_manifest_with_env(
    manifest: &Path,
    placement: &Path,
    storage_root: &Path,
    extra_env: &[(&str, &str)],
) -> RunHandle {
    run_manifest_with_args_and_env(manifest, placement, storage_root, &[], extra_env)
}

pub(crate) fn run_manifest_detached(
    manifest: &Path,
    placement: &Path,
    storage_root: &Path,
) -> RunHandle {
    run_manifest_with_args(manifest, placement, storage_root, &["--detach"])
}

pub(crate) fn run_manifest_expect_failure(
    manifest: &Path,
    placement: &Path,
    storage_root: &Path,
    extra_args: &[&str],
) -> FailedRun {
    run_manifest_expect_failure_with_env(manifest, placement, storage_root, extra_args, &[])
}

pub(crate) fn run_manifest_expect_failure_with_env(
    manifest: &Path,
    placement: &Path,
    storage_root: &Path,
    extra_args: &[&str],
    extra_env: &[(&str, &str)],
) -> FailedRun {
    let mut cmd = amber_command();
    cmd.arg("run")
        .arg(manifest)
        .arg("--placement")
        .arg(placement)
        .arg("--storage-root")
        .arg(storage_root)
        .args(extra_args)
        .envs(extra_env.iter().copied());
    let output = cmd.output().expect("failed to run amber run");
    assert!(
        !output.status.success(),
        "amber run unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    FailedRun {
        run_root: wait_for_single_run_root(storage_root, Duration::from_secs(60)),
        output,
    }
}

pub(crate) fn dry_run_manifest(
    manifest: &Path,
    placement: &Path,
    storage_root: &Path,
    bundle_root: &Path,
    extra_args: &[&str],
) -> std::process::Output {
    amber_command()
        .arg("run")
        .arg("-Z")
        .arg("unstable-options")
        .arg(manifest)
        .arg("--placement")
        .arg(placement)
        .arg("--storage-root")
        .arg(storage_root)
        .args(extra_args)
        .arg("--dry-run")
        .arg("--emit-launch-bundle")
        .arg(bundle_root)
        .output()
        .expect("failed to run amber run --dry-run")
}

pub(crate) fn spawn_run_manifest_with_env(
    manifest: &Path,
    placement: &Path,
    storage_root: &Path,
    extra_args: &[&str],
    extra_env: &[(&str, &str)],
) -> std::process::Child {
    amber_command()
        .arg("run")
        .arg(manifest)
        .arg("--placement")
        .arg(placement)
        .arg("--storage-root")
        .arg(storage_root)
        .args(extra_args)
        .envs(extra_env.iter().copied())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn amber run")
}

pub(crate) fn write_path_component(
    root: &Path,
    file_name: &str,
    name: &str,
    listen_port: u16,
    upstreams: &[(&str, &str)],
    extra_env: &[(&str, &str)],
) {
    let env = upstreams
        .iter()
        .map(|(alias, url)| {
            (
                format!("UPSTREAM_{}", alias.to_ascii_uppercase()),
                json!(url),
            )
        })
        .chain(
            extra_env
                .iter()
                .map(|(key, value)| ((*key).to_string(), json!(value))),
        )
        .chain(std::iter::once((
            "PORT".to_string(),
            json!(listen_port.to_string()),
        )))
        .chain(std::iter::once(("NAME".to_string(), json!(name))))
        .collect::<serde_json::Map<_, _>>();
    write_json(
        &root.join(file_name),
        &json!({
            "manifest_version": "0.3.0",
            "slots": upstreams.iter().map(|(alias, _)| ((*alias).to_string(), json!({"kind": "http"}))).collect::<serde_json::Map<_, _>>(),
            "program": {
                "path": "/usr/bin/env",
                "args": ["python3", "-u", "-c", { "file": "./app.py" }],
                "env": env,
                "network": {
                    "endpoints": [
                        { "name": "http", "port": listen_port, "protocol": "http" }
                    ]
                }
            },
            "provides": {
                "http": { "kind": "http", "endpoint": "http" }
            },
            "exports": {
                "http": "http"
            }
        }),
    );
}

pub(crate) fn write_image_component(
    root: &Path,
    file_name: &str,
    name: &str,
    listen_port: u16,
    upstreams: &[(&str, &str)],
    extra_env: &[(&str, &str)],
) {
    let env = upstreams
        .iter()
        .map(|(alias, url)| {
            (
                format!("UPSTREAM_{}", alias.to_ascii_uppercase()),
                json!(url),
            )
        })
        .chain(
            extra_env
                .iter()
                .map(|(key, value)| ((*key).to_string(), json!(value))),
        )
        .chain(std::iter::once((
            "PORT".to_string(),
            json!(listen_port.to_string()),
        )))
        .chain(std::iter::once(("NAME".to_string(), json!(name))))
        .collect::<serde_json::Map<_, _>>();
    write_json(
        &root.join(file_name),
        &json!({
            "manifest_version": "0.3.0",
            "slots": upstreams.iter().map(|(alias, _)| ((*alias).to_string(), json!({"kind": "http"}))).collect::<serde_json::Map<_, _>>(),
            "program": {
                "image": TEST_APP_IMAGE,
                "entrypoint": ["python3", "-u", "-c", { "file": "./app.py" }],
                "env": env,
                "network": {
                    "endpoints": [
                        { "name": "http", "port": listen_port, "protocol": "http" }
                    ]
                }
            },
            "provides": {
                "http": { "kind": "http", "endpoint": "http" }
            },
            "exports": {
                "http": "http"
            }
        }),
    );
}

pub(crate) fn render_vm_cloud_init(
    name: &str,
    listen_port: u16,
    upstreams: &[(&str, &str)],
    adversarial_host_url: Option<&str>,
) -> String {
    let upstream_lines = if upstreams.is_empty() {
        String::new()
    } else {
        upstreams
            .iter()
            .map(|(alias, url)| format!("      \"{alias}\": \"{}\",\n", url.replace('"', "\\\"")))
            .collect::<String>()
    };
    let adversarial_host_url = adversarial_host_url.unwrap_or("");
    format!(
        r#"#cloud-config
write_files:
  - path: /usr/local/bin/mixed-run-app.py
    permissions: '0755'
    content: |
      import json
      import os
      import socket
      import threading
      from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
      from urllib.parse import urlparse
      from urllib.request import Request, urlopen

      NAME = "{name}"
      PORT = {listen_port}
      UPSTREAMS = {{
{upstream_lines}      }}
      ADVERSARIAL_HOST_URL = "{adversarial_host_url}".rstrip("/")

      def fetch_text(url: str, timeout: float = 10.0) -> str:
          request = Request(url, headers={{"Connection": "close"}})
          with urlopen(request, timeout=timeout) as response:
              return response.read().decode("utf-8")

      def fetch_host_probe(url: str, timeout: float = 1.0) -> str:
          parsed = urlparse(url)
          host = parsed.hostname
          if not host:
              raise ValueError("missing host")
          port = parsed.port or 80
          path = parsed.path or "/"
          if parsed.query:
              path += "?" + parsed.query
          with socket.create_connection((host, port), timeout=timeout) as sock:
              sock.settimeout(timeout)
              request = (
                  f"GET {{path}} HTTP/1.1\\r\\n"
                  f"Host: {{host}}\\r\\n"
                  "Connection: close\\r\\n\\r\\n"
              ).encode("utf-8")
              sock.sendall(request)
              chunks = []
              while True:
                  chunk = sock.recv(4096)
                  if not chunk:
                      break
                  chunks.append(chunk)
          _, _, body = b"".join(chunks).decode("utf-8", errors="replace").partition("\\r\\n\\r\\n")
          return body

      def send(handler: BaseHTTPRequestHandler, status: int, body: str) -> None:
          payload = body.encode("utf-8")
          handler.send_response(status)
          handler.send_header("content-type", "text/plain; charset=utf-8")
          handler.send_header("content-length", str(len(payload)))
          handler.end_headers()
          handler.wfile.write(payload)

      class Handler(BaseHTTPRequestHandler):
          def do_GET(self) -> None:
              if self.path == "/id":
                  send(self, 200, NAME)
                  return
              if self.path == "/upstreams":
                  send(self, 200, json.dumps(sorted(UPSTREAMS)))
                  return
              if self.path.startswith("/call/"):
                  alias = self.path.removeprefix("/call/")
                  upstream = UPSTREAMS.get(alias)
                  if not upstream:
                      send(self, 404, f"missing upstream {{alias}}")
                      return
                  send(self, 200, fetch_text(f"{{upstream}}/id"))
                  return
              if self.path == "/adversarial-host":
                  if not ADVERSARIAL_HOST_URL:
                      send(self, 404, "missing adversarial host URL")
                      return
                  try:
                      send(self, 200, fetch_host_probe(ADVERSARIAL_HOST_URL, timeout=1.0))
                  except Exception as err:
                      send(self, 200, f"blocked:{{err.__class__.__name__}}")
                  return
              if self.path == "/crash":
                  def crash() -> None:
                      os._exit(42)

                  threading.Thread(target=crash, daemon=True).start()
                  send(self, 202, "crashing")
                  return
              send(self, 200, "ok")

          def log_message(self, fmt: str, *args: object) -> None:
              print(f"[{{NAME}}] {{fmt % args}}", flush=True)

      ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
  - path: /etc/systemd/system/mixed-run-app.service
    permissions: '0644'
    content: |
      [Unit]
      Description=Amber mixed-run VM test app

      [Service]
      ExecStart=/usr/bin/python3 /usr/local/bin/mixed-run-app.py
      Restart=always

      [Install]
      WantedBy=multi-user.target
runcmd:
  - [systemctl, daemon-reload]
  - [systemctl, enable, --now, mixed-run-app.service]
"#
    )
}

pub(crate) struct VmComponentSpec<'a> {
    pub(crate) file_name: &'a str,
    pub(crate) cloud_init_name: &'a str,
    pub(crate) name: &'a str,
    pub(crate) listen_port: u16,
    pub(crate) base_image: &'a Path,
    pub(crate) upstreams: &'a [(&'a str, &'a str)],
    pub(crate) adversarial_host_url: Option<&'a str>,
}

pub(crate) fn write_vm_component(root: &Path, spec: VmComponentSpec<'_>) {
    fs::write(
        root.join(spec.cloud_init_name),
        render_vm_cloud_init(
            spec.name,
            spec.listen_port,
            spec.upstreams,
            spec.adversarial_host_url,
        ),
    )
    .unwrap_or_else(|err| {
        panic!(
            "failed to write {}: {err}",
            root.join(spec.cloud_init_name).display()
        )
    });
    write_json(
        &root.join(spec.file_name),
        &json!({
            "manifest_version": "0.3.0",
            "slots": spec.upstreams.iter().map(|(alias, _)| ((*alias).to_string(), json!({"kind": "http"}))).collect::<serde_json::Map<_, _>>(),
            "program": {
                "vm": {
                    "image": spec.base_image.display().to_string(),
                    "cpus": 2,
                    "memory_mib": 768,
                    "cloud_init": {
                        "user_data": { "file": format!("./{}", spec.cloud_init_name) }
                    },
                    "network": {
                        "endpoints": [
                            { "name": "http", "port": spec.listen_port, "protocol": "http" }
                        ],
                        "egress": "none"
                    }
                }
            },
            "provides": {
                "http": { "kind": "http", "endpoint": "http" }
            },
            "exports": {
                "http": "http"
            }
        }),
    );
}

pub(crate) struct HostHttpServer {
    port: u16,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl HostHttpServer {
    pub(crate) fn start() -> Self {
        let listener = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
            .expect("failed to bind host http server");
        let port = listener.local_addr().expect("host http server addr").port();
        listener
            .set_nonblocking(true)
            .expect("host http server should be nonblocking");
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !stop_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => serve_host_http_request(&mut stream),
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        wait_for_condition(
            Duration::from_secs(10),
            || matches!(http_get(port, "/"), Some((200, _))),
            &format!("host http server on 127.0.0.1:{port}"),
        );
        Self {
            port,
            stop,
            thread: Some(thread),
        }
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for HostHttpServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], self.port)));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub(crate) fn serve_host_http_request(stream: &mut TcpStream) {
    let mut request = [0u8; 1024];
    let _ = stream.read(&mut request);
    let request = String::from_utf8_lossy(&request);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    let (content_type, body) = match path {
        "/item/amber-mug" => (
            "application/json; charset=utf-8",
            r#"{"source":"external","item":"amber mug"}"#,
        ),
        "/health" => ("application/json; charset=utf-8", r#"{"ok":true}"#),
        _ => ("text/plain; charset=utf-8", "ok"),
    };
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\nConnection: \
         close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

pub(crate) struct KindClusterGuard {
    name: String,
    kubeconfig: PathBuf,
}

impl KindClusterGuard {
    pub(crate) fn new(name: String, kubeconfig: &Path) -> Self {
        let _ = kind_cmd(kubeconfig)
            .arg("delete")
            .arg("cluster")
            .arg("--name")
            .arg(&name)
            .status();
        let status = kind_cmd(kubeconfig)
            .arg("create")
            .arg("cluster")
            .arg("--name")
            .arg(&name)
            .arg("--kubeconfig")
            .arg(kubeconfig)
            .arg("--wait")
            .arg("120s")
            .status()
            .expect("failed to run kind create cluster");
        if !status.success() {
            let _ = kind_cmd(kubeconfig)
                .arg("delete")
                .arg("cluster")
                .arg("--name")
                .arg(&name)
                .arg("--kubeconfig")
                .arg(kubeconfig)
                .status();
            panic!("kind create cluster failed with status {status}");
        }
        Self {
            name,
            kubeconfig: kubeconfig.to_path_buf(),
        }
    }
}

impl Drop for KindClusterGuard {
    fn drop(&mut self) {
        let _ = kind_cmd(&self.kubeconfig)
            .arg("delete")
            .arg("cluster")
            .arg("--name")
            .arg(&self.name)
            .arg("--kubeconfig")
            .arg(&self.kubeconfig)
            .status();
    }
}

pub(crate) struct KindCluster {
    name: String,
    pub(crate) kubeconfig: PathBuf,
    _guard: Option<KindClusterGuard>,
}

impl KindCluster {
    pub(crate) fn from_env_or_create(default_kubeconfig: &Path) -> Self {
        match (
            env::var("AMBER_TEST_KIND_CLUSTER_NAME").ok(),
            env::var("AMBER_TEST_KIND_KUBECONFIG").ok(),
        ) {
            (Some(name), Some(kubeconfig)) => Self {
                name,
                kubeconfig: PathBuf::from(kubeconfig),
                _guard: None,
            },
            (None, None) => {
                let nonce = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("system time should be available")
                    .as_nanos();
                let name = format!("amber-mixed-run-{}-{nonce}", std::process::id());
                Self {
                    name: name.clone(),
                    kubeconfig: default_kubeconfig.to_path_buf(),
                    _guard: Some(KindClusterGuard::new(name, default_kubeconfig)),
                }
            }
            _ => panic!("set AMBER_TEST_KIND_CLUSTER_NAME and AMBER_TEST_KIND_KUBECONFIG together"),
        }
    }

    pub(crate) fn context_name(&self) -> String {
        format!("kind-{}", self.name)
    }
}

pub(crate) fn kind_cmd(kubeconfig: &Path) -> Command {
    let mut cmd = Command::new("kind");
    cmd.env("KUBECONFIG", kubeconfig);
    cmd
}

pub(crate) fn kubectl_cmd(kubeconfig: &Path) -> Command {
    let mut cmd = Command::new("kubectl");
    cmd.env("KUBECONFIG", kubeconfig);
    cmd
}

pub(crate) struct ScenarioFixture {
    pub(crate) manifest: PathBuf,
    pub(crate) placement: PathBuf,
}

pub(crate) fn copy_documented_mixed_site_fixture(root: &Path) -> ScenarioFixture {
    let source_root = workspace_root().join("examples").join("mixed-site");
    for file_name in [
        "scenario.json5",
        "local-placement.json5",
        "web.json5",
        "api.json5",
        "web.py",
        "api.py",
        "mock-catalog.py",
    ] {
        fs::copy(source_root.join(file_name), root.join(file_name)).unwrap_or_else(|err| {
            panic!(
                "failed to copy documented mixed-site file {}: {err}",
                source_root.join(file_name).display()
            )
        });
    }

    let web_port = pick_free_port();
    let mut api_port = pick_free_port();
    while api_port == web_port {
        api_port = pick_free_port();
    }
    rewrite_documented_port(root.join("web.json5"), web_port);
    rewrite_documented_port(root.join("api.json5"), api_port);

    ScenarioFixture {
        manifest: root.join("scenario.json5"),
        placement: root.join("local-placement.json5"),
    }
}

pub(crate) fn rewrite_documented_port(path: PathBuf, port: u16) {
    let contents = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let contents = contents
        .replace("PORT: \"8080\"", &format!("PORT: \"{port}\""))
        .replace("port: 8080", &format!("port: {port}"));
    fs::write(&path, contents)
        .unwrap_or_else(|err| panic!("failed to update {}: {err}", path.display()));
}

pub(crate) fn write_two_site_fixture(root: &Path) -> ScenarioFixture {
    fs::write(root.join("app.py"), COMMON_HTTP_APP).expect("failed to write app.py");

    let direct_port = pick_free_port();
    write_path_component(
        root,
        "a.json5",
        "A",
        direct_port,
        &[("b", "${slots.b.url}")],
        &[],
    );
    write_image_component(root, "b.json5", "B", 8080, &[], &[]);

    let manifest = root.join("root.json5");
    write_json(
        &manifest,
        &json!({
            "manifest_version": "0.3.0",
            "components": {
                "a": "./a.json5",
                "b": "./b.json5"
            },
            "bindings": [
                { "to": "#a.b", "from": "#b.http" }
            ],
            "exports": {
                "a_http": "#a.http",
                "b_http": "#b.http"
            }
        }),
    );

    let placement = root.join("placement.json5");
    write_json(
        &placement,
        &json!({
            "schema": "amber.run.placement",
            "version": 1,
            "sites": {
                "direct_local": { "kind": "direct" },
                "compose_local": { "kind": "compose" }
            },
            "defaults": {
                "path": "direct_local",
                "image": "compose_local"
            }
        }),
    );

    ScenarioFixture {
        manifest,
        placement,
    }
}

pub(crate) fn write_single_site_direct_fixture(root: &Path) -> ScenarioFixture {
    fs::write(root.join("app.py"), COMMON_HTTP_APP).expect("failed to write app.py");

    let direct_port = pick_free_port();
    write_path_component(root, "a.json5", "A", direct_port, &[], &[]);

    let manifest = root.join("root.json5");
    write_json(
        &manifest,
        &json!({
            "manifest_version": "0.3.0",
            "components": {
                "a": "./a.json5"
            },
            "exports": {
                "a_http": "#a.http"
            }
        }),
    );

    let placement = root.join("placement.json5");
    write_json(
        &placement,
        &json!({
            "schema": "amber.run.placement",
            "version": 1,
            "sites": {
                "direct_local": { "kind": "direct" }
            },
            "defaults": {
                "path": "direct_local"
            }
        }),
    );

    ScenarioFixture {
        manifest,
        placement,
    }
}

pub(crate) fn write_single_site_vm_fixture(root: &Path) -> ScenarioFixture {
    fs::write(root.join("app.py"), COMMON_HTTP_APP).expect("failed to write app.py");
    let base_image = mixed_run_base_image();
    assert!(
        base_image.is_file(),
        "mixed-site VM test requires {}\nset AMBER_MIXED_RUN_BASE_IMAGE to override",
        base_image.display()
    );

    write_vm_component(
        root,
        VmComponentSpec {
            file_name: "a.json5",
            cloud_init_name: "a.cloud-init.yaml",
            name: "A",
            listen_port: 8080,
            base_image: &base_image,
            upstreams: &[],
            adversarial_host_url: None,
        },
    );

    let manifest = root.join("root.json5");
    write_json(
        &manifest,
        &json!({
            "manifest_version": "0.3.0",
            "components": {
                "a": "./a.json5"
            },
            "exports": {
                "a_http": "#a.http"
            }
        }),
    );

    let placement = root.join("placement.json5");
    write_json(
        &placement,
        &json!({
            "schema": "amber.run.placement",
            "version": 1,
            "sites": {
                "vm_local": { "kind": "vm" }
            },
            "defaults": {
                "vm": "vm_local"
            }
        }),
    );

    ScenarioFixture {
        manifest,
        placement,
    }
}

pub(crate) fn write_single_site_kind_fixture(
    root: &Path,
    kind_cluster: &KindCluster,
) -> ScenarioFixture {
    fs::write(root.join("app.py"), COMMON_HTTP_APP).expect("failed to write app.py");
    write_image_component(root, "a.json5", "A", 8080, &[], &[]);

    let manifest = root.join("root.json5");
    write_json(
        &manifest,
        &json!({
            "manifest_version": "0.3.0",
            "components": {
                "a": "./a.json5"
            },
            "exports": {
                "a_http": "#a.http"
            }
        }),
    );

    let placement = root.join("placement.json5");
    write_json(
        &placement,
        &json!({
            "schema": "amber.run.placement",
            "version": 1,
            "sites": {
                "kind_local": { "kind": "kubernetes", "context": kind_cluster.context_name() }
            },
            "defaults": {
                "image": "kind_local"
            }
        }),
    );

    ScenarioFixture {
        manifest,
        placement,
    }
}

pub(crate) fn write_partial_launch_failure_fixture(root: &Path) -> ScenarioFixture {
    fs::write(root.join("app.py"), COMMON_HTTP_APP).expect("failed to write app.py");
    write_image_component(root, "b.json5", "B", 8080, &[], &[]);
    write_image_component(root, "c.json5", "C", 8080, &[("b", "${slots.b.url}")], &[]);

    let manifest = root.join("root.json5");
    write_json(
        &manifest,
        &json!({
            "manifest_version": "0.3.0",
            "components": {
                "b": "./b.json5",
                "c": "./c.json5"
            },
            "bindings": [
                { "to": "#c.b", "from": "#b.http" }
            ],
            "exports": {
                "b_http": "#b.http",
                "c_http": "#c.http"
            }
        }),
    );

    let placement = root.join("placement.json5");
    write_json(
        &placement,
        &json!({
            "schema": "amber.run.placement",
            "version": 1,
            "sites": {
                "compose_local": { "kind": "compose" },
                "missing_kind": {
                    "kind": "kubernetes",
                    "context": "amber-context-that-does-not-exist"
                }
            },
            "defaults": {
                "image": "compose_local"
            },
            "components": {
                "/c": "missing_kind"
            }
        }),
    );

    ScenarioFixture {
        manifest,
        placement,
    }
}

pub(crate) fn write_precommit_cleanup_fixture(root: &Path) -> ScenarioFixture {
    fs::write(root.join("app.py"), COMMON_HTTP_APP).expect("failed to write app.py");
    let base_image = mixed_run_base_image();
    assert!(
        base_image.is_file(),
        "mixed-site VM test requires {}\nset AMBER_MIXED_RUN_BASE_IMAGE to override",
        base_image.display()
    );

    write_image_component(root, "b.json5", "B", 8080, &[], &[]);
    write_vm_component(
        root,
        VmComponentSpec {
            file_name: "a.json5",
            cloud_init_name: "a.cloud-init.yaml",
            name: "A",
            listen_port: 8080,
            base_image: &base_image,
            upstreams: &[("b", "${slots.b.url}")],
            adversarial_host_url: None,
        },
    );

    let manifest = root.join("root.json5");
    write_json(
        &manifest,
        &json!({
            "manifest_version": "0.3.0",
            "components": {
                "a": "./a.json5",
                "b": "./b.json5"
            },
            "bindings": [
                { "to": "#a.b", "from": "#b.http" }
            ],
            "exports": {
                "b_http": "#b.http"
            }
        }),
    );

    let placement = root.join("placement.json5");
    write_json(
        &placement,
        &json!({
            "schema": "amber.run.placement",
            "version": 1,
            "sites": {
                "vm_local": { "kind": "vm" },
                "compose_local": { "kind": "compose" }
            },
            "defaults": {
                "vm": "vm_local",
                "image": "compose_local"
            },
            "components": {
                "/a": "vm_local",
                "/b": "compose_local"
            }
        }),
    );

    ScenarioFixture {
        manifest,
        placement,
    }
}

pub(crate) fn write_five_site_fixture(
    root: &Path,
    kind_cluster: &KindCluster,
    adversarial_host_port: u16,
) -> ScenarioFixture {
    fs::write(root.join("app.py"), COMMON_HTTP_APP).expect("failed to write app.py");
    let base_image = mixed_run_base_image();
    let adversarial_host_url = docker_host_http_url(adversarial_host_port);
    assert!(
        base_image.is_file(),
        "mixed-site VM test requires {}\nset AMBER_MIXED_RUN_BASE_IMAGE to override",
        base_image.display()
    );

    let direct_port = pick_free_port();
    write_path_component(
        root,
        "a.json5",
        "A",
        direct_port,
        &[("b", "${slots.b.url}"), ("c", "${slots.c.url}")],
        &[],
    );
    write_image_component(
        root,
        "b.json5",
        "B",
        8080,
        &[("c", "${slots.c.url}"), ("d", "${slots.d.url}")],
        &[("ADVERSARIAL_HOST_URL", &adversarial_host_url)],
    );
    write_image_component(root, "c.json5", "C", 8080, &[("d", "${slots.d.url}")], &[]);
    write_vm_component(
        root,
        VmComponentSpec {
            file_name: "d.json5",
            cloud_init_name: "d.cloud-init.yaml",
            name: "D",
            listen_port: 8080,
            base_image: &base_image,
            upstreams: &[("e", "${slots.e.url}")],
            adversarial_host_url: None,
        },
    );
    write_image_component(
        root,
        "e.json5",
        "E",
        8080,
        &[],
        &[("ADVERSARIAL_HOST_URL", &adversarial_host_url)],
    );

    let manifest = root.join("root.json5");
    write_json(
        &manifest,
        &json!({
            "manifest_version": "0.3.0",
            "components": {
                "a": "./a.json5",
                "b": "./b.json5",
                "c": "./c.json5",
                "d": "./d.json5",
                "e": "./e.json5"
            },
            "bindings": [
                { "to": "#a.b", "from": "#b.http" },
                { "to": "#a.c", "from": "#c.http" },
                { "to": "#b.c", "from": "#c.http" },
                { "to": "#b.d", "from": "#d.http" },
                { "to": "#c.d", "from": "#d.http" },
                { "to": "#d.e", "from": "#e.http" }
            ],
            "exports": {
                "a_http": "#a.http",
                "b_http": "#b.http",
                "c_http": "#c.http",
                "d_http": "#d.http",
                "e_http": "#e.http"
            }
        }),
    );

    let placement = root.join("placement.json5");
    write_json(
        &placement,
        &json!({
            "schema": "amber.run.placement",
            "version": 1,
            "sites": {
                "direct_a": { "kind": "direct" },
                "compose_b": { "kind": "compose" },
                "kind_c": { "kind": "kubernetes", "context": kind_cluster.context_name() },
                "vm_d": { "kind": "vm" },
                "compose_e": { "kind": "compose" }
            },
            "defaults": {
                "path": "direct_a",
                "vm": "vm_d",
                "image": "compose_b"
            },
            "components": {
                "/a": "direct_a",
                "/b": "compose_b",
                "/c": "kind_c",
                "/d": "vm_d",
                "/e": "compose_e"
            }
        }),
    );

    ScenarioFixture {
        manifest,
        placement,
    }
}

pub(crate) fn wait_for_state_status(
    run_root: &Path,
    site_id: &str,
    status: &str,
    timeout: Duration,
) -> Value {
    let state_path = run_root
        .join("state")
        .join(site_id)
        .join("manager-state.json");
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if state_path.is_file() {
            let state = read_json(&state_path);
            if state["status"] == status {
                return state;
            }
        }
        thread::sleep(Duration::from_millis(250));
    }
    panic!(
        "timed out waiting for site {site_id} state {status}\nlast state:\n{}{}",
        if state_path.is_file() {
            fs::read_to_string(&state_path).unwrap_or_default()
        } else {
            String::from("<missing>")
        },
        site_debug_context(run_root, site_id),
    );
}

pub(crate) fn compose_ps_ids(project: &str, artifact_dir: &Path) -> String {
    compose_ps_ids_with_env(project, artifact_dir, &[])
}

pub(crate) fn compose_ps_ids_with_env(
    project: &str,
    artifact_dir: &Path,
    extra_env: &[(&str, &str)],
) -> String {
    let output = Command::new("docker")
        .arg("compose")
        .arg("-f")
        .arg(artifact_dir.join("compose.yaml"))
        .arg("-p")
        .arg(project)
        .arg("ps")
        .arg("-q")
        .envs(extra_env.iter().copied())
        .output()
        .expect("failed to query docker compose ps");
    assert!(
        output.status.success(),
        "docker compose ps failed for {project}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

pub(crate) fn namespace_exists(namespace: &str, kubeconfig: &Path, context: &str) -> bool {
    kubectl_cmd(kubeconfig)
        .arg("--context")
        .arg(context)
        .arg("get")
        .arg("namespace")
        .arg(namespace)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}
