#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::{
    collections::BTreeSet,
    env, fs,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Mutex, OnceLock},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use amber_images::{AMBER_HELPER, AMBER_PROVISIONER, AMBER_ROUTER};
use serde_json::{Value, json};

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

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root")
        .to_path_buf()
}

fn outputs_root() -> PathBuf {
    workspace_root().join("target").join("cli-test-outputs")
}

struct TestTempDir {
    path: PathBuf,
    _guard: Option<tempfile::TempDir>,
}

impl TestTempDir {
    fn path(&self) -> &Path {
        &self.path
    }
}

fn cargo_target_dir() -> PathBuf {
    match env::var_os("CARGO_TARGET_DIR") {
        Some(dir) => {
            let dir = PathBuf::from(dir);
            if dir.is_absolute() {
                dir
            } else {
                workspace_root().join(dir)
            }
        }
        None => workspace_root().join("target"),
    }
}

fn runtime_bin_dir() -> &'static PathBuf {
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
            .output()
            .expect("failed to build amber runtime binaries");
        assert!(
            output.status.success(),
            "failed to build runtime binaries\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        cargo_target_dir().join("debug")
    })
}

fn mixed_run_base_image() -> PathBuf {
    env::var_os("AMBER_MIXED_RUN_BASE_IMAGE")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root().join("ubuntu-24.04-minimal-cloudimg-arm64.img"))
}

fn temp_output_dir(prefix: &str) -> TestTempDir {
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

fn pick_free_port() -> u16 {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    listener.local_addr().unwrap().port()
}

fn docker_host_ip() -> String {
    let mut cmd = Command::new("docker");
    cmd.arg("run").arg("--rm");
    #[cfg(target_os = "linux")]
    {
        cmd.arg("--add-host")
            .arg("host.docker.internal:host-gateway");
    }
    let output = cmd
        .arg("python:3.13-alpine")
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

fn docker_host_http_url(port: u16) -> String {
    format!("http://{}:{port}/", docker_host_ip())
}

fn write_json(path: &Path, value: &Value) {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).expect("test fixture should serialize"),
    )
    .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(
        &fs::read(path).unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display())),
    )
    .unwrap_or_else(|err| panic!("invalid JSON {}: {err}", path.display()))
}

fn http_get(port: u16, path: &str) -> Option<(u16, String)> {
    let output = Command::new("curl")
        .arg("-sS")
        .arg("--max-time")
        .arg("5")
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

fn wait_for_body(port: u16, path: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some((200, body)) = http_get(port, path) {
            return body;
        }
        thread::sleep(Duration::from_millis(250));
    }
    panic!("timed out waiting for http://127.0.0.1:{port}{path}");
}

fn wait_for_path(port: u16, path: &str, timeout: Duration) {
    let _ = wait_for_body(port, path, timeout);
}

fn wait_for_condition(timeout: Duration, mut predicate: impl FnMut() -> bool, label: &str) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if predicate() {
            return;
        }
        thread::sleep(Duration::from_millis(250));
    }
    panic!("timed out waiting for {label}");
}

fn wait_for_file(path: &Path, timeout: Duration) {
    wait_for_condition(
        timeout,
        || path.is_file(),
        &format!("file {}", path.display()),
    );
}

fn wait_for_single_run_root(storage_root: &Path, timeout: Duration) -> PathBuf {
    let runs_dir = storage_root.join("runs");
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let mut runs = fs::read_dir(&runs_dir)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.is_dir())
            .collect::<Vec<_>>();
        runs.sort();
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

fn wait_for_state_pid_change(
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

fn wait_for_text(path: &Path, needle: &str, timeout: Duration) -> String {
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

fn spawn_proxy(
    output_dir: &Path,
    export: &str,
    local_port: u16,
    extra_args: &[String],
) -> std::process::Child {
    spawn_proxy_with_exports(output_dir, &[(export, local_port)], extra_args)
}

fn spawn_proxy_with_exports(
    output_dir: &Path,
    exports: &[(&str, u16)],
    extra_args: &[String],
) -> std::process::Child {
    let stdout = Stdio::null();
    let stderr = Stdio::null();
    let mut cmd = amber_command();
    cmd.arg("proxy").arg(output_dir);
    for (export, local_port) in exports {
        cmd.arg("--export")
            .arg(format!("{export}=127.0.0.1:{local_port}"));
    }
    cmd.args(extra_args).stdout(stdout).stderr(stderr);
    cmd.spawn().expect("failed to start amber proxy")
}

fn stop_child(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn amber_command() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_amber"));
    cmd.env("AMBER_RUNTIME_BIN_DIR", runtime_bin_dir());
    if let Some(kubeconfig) = env::var_os("AMBER_TEST_KIND_KUBECONFIG") {
        cmd.env("KUBECONFIG", kubeconfig);
    }
    cmd
}

fn use_prebuilt_images() -> bool {
    env::var_os("AMBER_TEST_USE_PREBUILT_IMAGES").is_some()
}

fn image_platform_opt(tag: &str) -> Option<String> {
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

fn ensure_docker_image(tag: &str, dockerfile: &Path) {
    if use_prebuilt_images() {
        image_platform_opt(tag).unwrap_or_else(|| {
            panic!(
                "AMBER_TEST_USE_PREBUILT_IMAGES is set but {tag} is not available locally. Ensure \
                 the image is pulled and retagged before running mixed-run tests."
            )
        });
        return;
    }

    let status = Command::new("docker")
        .arg("buildx")
        .arg("build")
        .arg("--load")
        .arg("-t")
        .arg(tag)
        .arg("-f")
        .arg(dockerfile)
        .arg(workspace_root())
        .status()
        .unwrap_or_else(|err| panic!("failed to build {tag}: {err}"));
    assert!(status.success(), "docker build failed for {tag}");
}

fn ensure_internal_images() {
    static READY: OnceLock<()> = OnceLock::new();
    READY.get_or_init(|| {
        let root = workspace_root();
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

fn load_kind_image(cluster_name: &str, image: &str) {
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

fn ensure_kind_internal_images(kind_cluster: &KindCluster) {
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
    loaded
        .lock()
        .expect("kind image-load guard should lock")
        .insert(name);
}

fn kill_pid(pid: u32) {
    #[cfg(unix)]
    unsafe {
        let _ = libc::kill(pid as i32, libc::SIGTERM);
    }
}

fn pid_is_alive(pid: u32) -> bool {
    #[cfg(unix)]
    unsafe {
        libc::kill(pid as i32, 0) == 0
            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }

    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

#[derive(Debug)]
struct RunHandle {
    run_id: String,
    run_root: PathBuf,
    receipt: Value,
    storage_root: PathBuf,
    stopped: bool,
}

struct FailedRun {
    output: std::process::Output,
    run_root: PathBuf,
}

impl RunHandle {
    fn site_artifact_dir(&self, site_id: &str) -> PathBuf {
        PathBuf::from(
            self.receipt["sites"][site_id]["artifact_dir"]
                .as_str()
                .unwrap_or_else(|| panic!("missing artifact_dir for site {site_id}")),
        )
    }

    fn stop(&mut self) {
        if self.stopped {
            return;
        }
        let output = amber_command()
            .arg("stop")
            .arg(&self.run_id)
            .arg("--storage-root")
            .arg(&self.storage_root)
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
            .output();
        self.stopped = true;
    }
}

fn parse_run_id(stdout: &[u8]) -> String {
    String::from_utf8_lossy(stdout)
        .lines()
        .find_map(|line| line.strip_prefix("run_id="))
        .expect("amber run should print run_id")
        .to_string()
}

fn wait_for_receipt(storage_root: &Path, run_id: &str, timeout: Duration) -> Value {
    let receipt_path = storage_root.join("runs").join(run_id).join("receipt.json");
    wait_for_file(&receipt_path, timeout);
    read_json(&receipt_path)
}

fn run_manifest_with_args(
    manifest: &Path,
    placement: &Path,
    storage_root: &Path,
    extra_args: &[&str],
) -> RunHandle {
    let output = amber_command()
        .arg("run")
        .arg(manifest)
        .arg("--placement")
        .arg(placement)
        .arg("--storage-root")
        .arg(storage_root)
        .args(extra_args)
        .output()
        .expect("failed to run amber run");
    assert!(
        output.status.success(),
        "amber run failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let run_id = parse_run_id(&output.stdout);
    let run_root = storage_root.join("runs").join(&run_id);
    let receipt = wait_for_receipt(storage_root, &run_id, Duration::from_secs(240));
    RunHandle {
        run_id,
        run_root,
        receipt,
        storage_root: storage_root.to_path_buf(),
        stopped: false,
    }
}

fn run_manifest(manifest: &Path, placement: &Path, storage_root: &Path) -> RunHandle {
    run_manifest_with_args(manifest, placement, storage_root, &[])
}

fn run_manifest_detached(manifest: &Path, placement: &Path, storage_root: &Path) -> RunHandle {
    run_manifest_with_args(manifest, placement, storage_root, &["--detach"])
}

fn run_manifest_expect_failure(
    manifest: &Path,
    placement: &Path,
    storage_root: &Path,
    extra_args: &[&str],
) -> FailedRun {
    run_manifest_expect_failure_with_env(manifest, placement, storage_root, extra_args, &[])
}

fn run_manifest_expect_failure_with_env(
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

fn spawn_run_manifest_with_env(
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

fn write_path_component(
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

fn write_image_component(
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
                "image": "python:3.13-alpine",
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

fn render_vm_cloud_init(
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

struct VmComponentSpec<'a> {
    file_name: &'a str,
    cloud_init_name: &'a str,
    name: &'a str,
    listen_port: u16,
    base_image: &'a Path,
    upstreams: &'a [(&'a str, &'a str)],
    adversarial_host_url: Option<&'a str>,
}

fn write_vm_component(root: &Path, spec: VmComponentSpec<'_>) {
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

struct HostHttpServer {
    child: std::process::Child,
}

impl HostHttpServer {
    fn start(port: u16) -> Self {
        let child = Command::new("/usr/bin/env")
            .arg("python3")
            .arg("-u")
            .arg("-m")
            .arg("http.server")
            .arg(port.to_string())
            .arg("--bind")
            .arg("0.0.0.0")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to start host http server");
        wait_for_path(port, "/", Duration::from_secs(10));
        Self { child }
    }
}

impl Drop for HostHttpServer {
    fn drop(&mut self) {
        stop_child(&mut self.child);
    }
}

struct KindClusterGuard {
    name: String,
    kubeconfig: PathBuf,
}

impl KindClusterGuard {
    fn new(name: String, kubeconfig: &Path) -> Self {
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

struct KindCluster {
    name: String,
    kubeconfig: PathBuf,
    _guard: Option<KindClusterGuard>,
}

impl KindCluster {
    fn from_env_or_create(default_kubeconfig: &Path) -> Self {
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

    fn context_name(&self) -> String {
        format!("kind-{}", self.name)
    }
}

fn kind_cmd(kubeconfig: &Path) -> Command {
    let mut cmd = Command::new("kind");
    cmd.env("KUBECONFIG", kubeconfig);
    cmd
}

fn kubectl_cmd(kubeconfig: &Path) -> Command {
    let mut cmd = Command::new("kubectl");
    cmd.env("KUBECONFIG", kubeconfig);
    cmd
}

struct ScenarioFixture {
    manifest: PathBuf,
    placement: PathBuf,
}

fn write_two_site_fixture(root: &Path) -> ScenarioFixture {
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

fn write_single_site_direct_fixture(root: &Path) -> ScenarioFixture {
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

fn write_single_site_vm_fixture(root: &Path) -> ScenarioFixture {
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

fn write_single_site_kind_fixture(root: &Path, kind_cluster: &KindCluster) -> ScenarioFixture {
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

fn write_partial_launch_failure_fixture(root: &Path) -> ScenarioFixture {
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

fn write_precommit_cleanup_fixture(root: &Path) -> ScenarioFixture {
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

fn write_five_site_fixture(
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

fn wait_for_state_status(run_root: &Path, site_id: &str, status: &str, timeout: Duration) -> Value {
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
        "timed out waiting for site {site_id} state {status}\nlast state:\n{}",
        if state_path.is_file() {
            fs::read_to_string(&state_path).unwrap_or_default()
        } else {
            String::from("<missing>")
        }
    );
}

fn compose_ps_ids(project: &str, artifact_dir: &Path) -> String {
    let output = Command::new("docker")
        .arg("compose")
        .arg("-f")
        .arg(artifact_dir.join("compose.yaml"))
        .arg("-p")
        .arg(project)
        .arg("ps")
        .arg("-q")
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

fn namespace_exists(namespace: &str, kubeconfig: &Path, context: &str) -> bool {
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

#[test]
#[ignore = "requires docker + kind + kubectl + qemu + ubuntu-24.04-minimal-cloudimg-arm64.img; run \
            manually or in CI"]
fn mixed_run_five_site_startup_state_and_teardown() {
    let temp = temp_output_dir("mixed-run-five-site-");
    let kubeconfig = temp.path().join("kubeconfig");
    let kind_cluster = KindCluster::from_env_or_create(&kubeconfig);
    ensure_kind_internal_images(&kind_cluster);
    let adversarial_port = pick_free_port();
    let _host_server = HostHttpServer::start(adversarial_port);
    let fixture = write_five_site_fixture(temp.path(), &kind_cluster, adversarial_port);
    let storage_root = temp.path().join("state");
    let mut run = run_manifest(&fixture.manifest, &fixture.placement, &storage_root);

    let run_plan = read_json(&run.run_root.join("run-plan.json"));
    assert_eq!(
        run_plan["startup_waves"],
        json!([
            ["compose_e"],
            ["vm_d"],
            ["kind_c"],
            ["compose_b"],
            ["direct_a"]
        ])
    );
    assert_eq!(
        run_plan["assignments"],
        json!({
            "/a": "direct_a",
            "/b": "compose_b",
            "/c": "kind_c",
            "/d": "vm_d",
            "/e": "compose_e"
        })
    );
    assert_eq!(
        run.receipt["sites"]
            .as_object()
            .expect("receipt sites")
            .len(),
        5
    );

    let direct_state = wait_for_state_status(
        &run.run_root,
        "direct_a",
        "running",
        Duration::from_secs(30),
    );
    let compose_b_state = wait_for_state_status(
        &run.run_root,
        "compose_b",
        "running",
        Duration::from_secs(30),
    );
    let kind_state =
        wait_for_state_status(&run.run_root, "kind_c", "running", Duration::from_secs(60));
    let vm_state =
        wait_for_state_status(&run.run_root, "vm_d", "running", Duration::from_secs(180));
    let compose_e_state = wait_for_state_status(
        &run.run_root,
        "compose_e",
        "running",
        Duration::from_secs(30),
    );

    for (site_id, state) in [
        ("direct_a", &direct_state),
        ("compose_b", &compose_b_state),
        ("kind_c", &kind_state),
        ("vm_d", &vm_state),
        ("compose_e", &compose_e_state),
    ] {
        assert_eq!(state["run_id"], run.run_id);
        assert_eq!(state["site_id"], site_id);
        assert_eq!(state["status"], "running");
        assert_eq!(
            state["router_identity_id"],
            format!("/site/{site_id}/router")
        );
        assert!(
            state["router_control"].is_string(),
            "site {site_id} should publish router control"
        );
        let desired_links = read_json(
            &run.run_root
                .join("state")
                .join(site_id)
                .join("desired-links.json"),
        );
        assert_eq!(desired_links["schema"], "amber.run.desired_links");
    }

    assert_eq!(
        read_json(
            &run.run_root
                .join("state")
                .join("direct_a")
                .join("desired-links.json")
        )["external_slots"]
            .as_object()
            .expect("direct external slots")
            .len(),
        2
    );
    assert_eq!(
        read_json(
            &run.run_root
                .join("state")
                .join("compose_b")
                .join("desired-links.json")
        )["external_slots"]
            .as_object()
            .expect("compose_b external slots")
            .len(),
        2
    );
    assert_eq!(
        read_json(
            &run.run_root
                .join("state")
                .join("kind_c")
                .join("desired-links.json")
        )["external_slots"]
            .as_object()
            .expect("kind external slots")
            .len(),
        1
    );
    assert_eq!(
        read_json(
            &run.run_root
                .join("state")
                .join("vm_d")
                .join("desired-links.json")
        )["external_slots"]
            .as_object()
            .expect("vm external slots")
            .len(),
        1
    );

    let a_port = pick_free_port();
    let b_port = pick_free_port();
    let c_port = pick_free_port();
    let d_port = pick_free_port();
    let e_port = pick_free_port();
    let mut a_proxy = spawn_proxy(&run.site_artifact_dir("direct_a"), "a_http", a_port, &[]);
    let mut b_proxy = spawn_proxy(&run.site_artifact_dir("compose_b"), "b_http", b_port, &[]);
    let c_router_addr = kind_state["router_mesh_addr"]
        .as_str()
        .expect("kind site should publish router mesh addr")
        .to_string();
    let c_router_control = kind_state["router_control"]
        .as_str()
        .expect("kind site should publish router control")
        .to_string();
    let c_proxy_args = vec![
        "--router-addr".to_string(),
        c_router_addr,
        "--router-control-addr".to_string(),
        c_router_control,
    ];
    let mut c_proxy = spawn_proxy(
        &run.site_artifact_dir("kind_c"),
        "c_http",
        c_port,
        &c_proxy_args,
    );
    let mut d_proxy = spawn_proxy(&run.site_artifact_dir("vm_d"), "d_http", d_port, &[]);
    let mut e_proxy = spawn_proxy(&run.site_artifact_dir("compose_e"), "e_http", e_port, &[]);

    wait_for_path(a_port, "/id", Duration::from_secs(180));
    wait_for_path(b_port, "/id", Duration::from_secs(180));
    wait_for_path(c_port, "/id", Duration::from_secs(180));
    wait_for_path(d_port, "/id", Duration::from_secs(300));
    wait_for_path(e_port, "/id", Duration::from_secs(180));

    assert_eq!(
        wait_for_body(a_port, "/call/b", Duration::from_secs(120)),
        "B"
    );
    assert_eq!(
        wait_for_body(a_port, "/call/c", Duration::from_secs(120)),
        "C"
    );
    assert_eq!(
        wait_for_body(b_port, "/call/c", Duration::from_secs(120)),
        "C"
    );
    assert_eq!(
        wait_for_body(b_port, "/call/d", Duration::from_secs(120)),
        "D"
    );
    assert_eq!(
        wait_for_body(c_port, "/call/d", Duration::from_secs(120)),
        "D"
    );
    assert_eq!(
        wait_for_body(d_port, "/call/e", Duration::from_secs(120)),
        "E"
    );

    let b_adversarial = wait_for_body(b_port, "/adversarial-host", Duration::from_secs(60));
    let e_adversarial = wait_for_body(e_port, "/adversarial-host", Duration::from_secs(60));
    assert!(
        b_adversarial.starts_with("blocked:"),
        "compose site should not bypass Amber via host, got {b_adversarial}"
    );
    assert!(
        e_adversarial.starts_with("blocked:"),
        "compose site should not bypass Amber via host, got {e_adversarial}"
    );

    stop_child(&mut a_proxy);
    stop_child(&mut b_proxy);
    stop_child(&mut c_proxy);
    stop_child(&mut d_proxy);
    stop_child(&mut e_proxy);

    let direct_pid = direct_state["process_pid"]
        .as_u64()
        .expect("direct site pid should exist") as u32;
    let vm_pid = vm_state["process_pid"]
        .as_u64()
        .expect("vm site pid should exist") as u32;
    let compose_b_project = compose_b_state["compose_project"]
        .as_str()
        .expect("compose_b project should exist")
        .to_string();
    let compose_e_project = compose_e_state["compose_project"]
        .as_str()
        .expect("compose_e project should exist")
        .to_string();
    let kind_namespace = kind_state["kubernetes_namespace"]
        .as_str()
        .expect("kubernetes namespace should exist")
        .to_string();

    run.stop();
    wait_for_state_status(
        &run.run_root,
        "direct_a",
        "stopped",
        Duration::from_secs(30),
    );
    wait_for_state_status(
        &run.run_root,
        "compose_b",
        "stopped",
        Duration::from_secs(30),
    );
    wait_for_state_status(&run.run_root, "kind_c", "stopped", Duration::from_secs(60));
    wait_for_state_status(&run.run_root, "vm_d", "stopped", Duration::from_secs(60));
    wait_for_state_status(
        &run.run_root,
        "compose_e",
        "stopped",
        Duration::from_secs(30),
    );

    assert!(
        !run.run_root.join("receipt.json").exists(),
        "receipt should be removed after stop"
    );
    assert!(
        compose_ps_ids(&compose_b_project, &run.site_artifact_dir("compose_b")).is_empty(),
        "compose_b should be torn down"
    );
    assert!(
        compose_ps_ids(&compose_e_project, &run.site_artifact_dir("compose_e")).is_empty(),
        "compose_e should be torn down"
    );
    assert!(
        !namespace_exists(
            &kind_namespace,
            &kind_cluster.kubeconfig,
            &kind_cluster.context_name()
        ),
        "kubernetes namespace {kind_namespace} should be deleted"
    );
    assert!(
        !pid_is_alive(direct_pid),
        "direct site pid {direct_pid} should be gone"
    );
    assert!(!pid_is_alive(vm_pid), "vm site pid {vm_pid} should be gone");
}

#[test]
#[ignore = "requires docker; run manually or in CI"]
fn mixed_run_partial_site_failure_during_launch_cleans_up() {
    ensure_internal_images();
    let temp = temp_output_dir("mixed-run-launch-failure-");
    let fixture = write_partial_launch_failure_fixture(temp.path());
    let storage_root = temp.path().join("state");
    let failed =
        run_manifest_expect_failure(&fixture.manifest, &fixture.placement, &storage_root, &[]);

    let stdout = String::from_utf8_lossy(&failed.output.stdout);
    let stderr = String::from_utf8_lossy(&failed.output.stderr);
    assert!(
        stderr.contains("site supervisor for `missing_kind` exited before becoming ready")
            || stderr.contains("missing_kind"),
        "expected launch failure output\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !failed.run_root.join("receipt.json").exists(),
        "failed launch should not write a receipt"
    );
    assert!(
        !failed.run_root.join("committed").exists(),
        "failed launch should not commit"
    );

    let compose_state = wait_for_state_status(
        &failed.run_root,
        "compose_local",
        "stopped",
        Duration::from_secs(60),
    );
    let compose_project = compose_state["compose_project"]
        .as_str()
        .expect("compose project should be recorded")
        .to_string();
    assert!(
        compose_ps_ids(
            &compose_project,
            &failed
                .run_root
                .join("sites")
                .join("compose_local")
                .join("artifact")
        )
        .is_empty(),
        "compose site should be torn down after launch failure"
    );
}

#[test]
#[ignore = "requires docker + qemu + ubuntu-24.04-minimal-cloudimg-arm64.img; run manually or in CI"]
fn mixed_run_cleanup_after_coordinator_dies_during_setup() {
    ensure_internal_images();
    let temp = temp_output_dir("mixed-run-precommit-kill-");
    let fixture = write_precommit_cleanup_fixture(temp.path());
    let storage_root = temp.path().join("state");
    let mut run = spawn_run_manifest_with_env(
        &fixture.manifest,
        &fixture.placement,
        &storage_root,
        &[],
        &[("AMBER_TEST_MIXED_RUN_AFTER_WAVE_DELAY_MS", "5000")],
    );
    let run_root = wait_for_single_run_root(&storage_root, Duration::from_secs(60));

    let compose_state = wait_for_state_status(
        &run_root,
        "compose_local",
        "running",
        Duration::from_secs(60),
    );
    stop_child(&mut run);

    let compose_final = wait_for_state_status(
        &run_root,
        "compose_local",
        "stopped",
        Duration::from_secs(90),
    );
    assert_eq!(
        compose_final["last_error"],
        Value::String("coordinator exited before commit".to_string())
    );
    assert!(
        !run_root.join("receipt.json").exists(),
        "pre-commit coordinator exit should not leave a receipt"
    );
    assert!(
        !run_root.join("committed").exists(),
        "pre-commit coordinator exit should not commit"
    );

    let compose_project = compose_state["compose_project"]
        .as_str()
        .expect("compose project should be recorded")
        .to_string();
    assert!(
        compose_ps_ids(
            &compose_project,
            &run_root
                .join("sites")
                .join("compose_local")
                .join("artifact")
        )
        .is_empty(),
        "compose site should be torn down after coordinator death"
    );
}

#[test]
#[ignore = "requires a working direct runtime sandbox; run manually or in CI"]
fn mixed_run_recovers_direct_component_failure_after_setup() {
    let temp = temp_output_dir("mixed-run-direct-restart-");
    let fixture = write_single_site_direct_fixture(temp.path());
    let storage_root = temp.path().join("state");
    let mut run = run_manifest(&fixture.manifest, &fixture.placement, &storage_root);

    let direct_state = wait_for_state_status(
        &run.run_root,
        "direct_local",
        "running",
        Duration::from_secs(60),
    );
    let first_pid = direct_state["process_pid"]
        .as_u64()
        .expect("direct process pid should exist") as u32;

    let proxy_port = pick_free_port();
    let mut proxy = spawn_proxy(
        &run.site_artifact_dir("direct_local"),
        "a_http",
        proxy_port,
        &[],
    );
    wait_for_path(proxy_port, "/id", Duration::from_secs(60));
    let _ = http_get(proxy_port, "/crash");
    stop_child(&mut proxy);

    let recovered = wait_for_state_pid_change(
        &run.run_root,
        "direct_local",
        "process_pid",
        first_pid,
        Duration::from_secs(60),
    );
    assert_ne!(
        recovered["process_pid"]
            .as_u64()
            .expect("replacement direct pid should exist") as u32,
        first_pid
    );
    wait_for_state_status(
        &run.run_root,
        "direct_local",
        "running",
        Duration::from_secs(60),
    );

    let proxy_port = pick_free_port();
    let mut proxy = spawn_proxy(
        &run.site_artifact_dir("direct_local"),
        "a_http",
        proxy_port,
        &[],
    );
    assert_eq!(
        wait_for_body(proxy_port, "/id", Duration::from_secs(60)),
        "A"
    );
    stop_child(&mut proxy);
    run.stop();
}

#[test]
#[ignore = "requires qemu + ubuntu-24.04-minimal-cloudimg-arm64.img; run manually or in CI"]
fn mixed_run_recovers_vm_site_failure_after_setup() {
    let temp = temp_output_dir("mixed-run-vm-restart-");
    let fixture = write_single_site_vm_fixture(temp.path());
    let storage_root = temp.path().join("state");
    let mut run = run_manifest(&fixture.manifest, &fixture.placement, &storage_root);

    let vm_state = wait_for_state_status(
        &run.run_root,
        "vm_local",
        "running",
        Duration::from_secs(300),
    );
    let first_pid = vm_state["process_pid"]
        .as_u64()
        .expect("vm site pid should exist") as u32;

    let proxy_port = pick_free_port();
    let mut proxy = spawn_proxy(
        &run.site_artifact_dir("vm_local"),
        "a_http",
        proxy_port,
        &[],
    );
    wait_for_path(proxy_port, "/id", Duration::from_secs(300));
    stop_child(&mut proxy);

    kill_pid(first_pid);
    let recovered = wait_for_state_pid_change(
        &run.run_root,
        "vm_local",
        "process_pid",
        first_pid,
        Duration::from_secs(360),
    );
    assert_ne!(
        recovered["process_pid"]
            .as_u64()
            .expect("replacement vm pid should exist") as u32,
        first_pid
    );
    wait_for_state_status(
        &run.run_root,
        "vm_local",
        "running",
        Duration::from_secs(360),
    );

    let proxy_port = pick_free_port();
    let mut proxy = spawn_proxy(
        &run.site_artifact_dir("vm_local"),
        "a_http",
        proxy_port,
        &[],
    );
    assert_eq!(
        wait_for_body(proxy_port, "/id", Duration::from_secs(300)),
        "A"
    );
    stop_child(&mut proxy);
    run.stop();
}

#[test]
#[ignore = "requires docker + kind + kubectl; run manually or in CI"]
fn mixed_run_recovers_when_kubernetes_site_is_temporarily_unreachable() {
    let temp = temp_output_dir("mixed-run-kind-forward-restart-");
    let kubeconfig = temp.path().join("kubeconfig");
    let kind_cluster = KindCluster::from_env_or_create(&kubeconfig);
    ensure_kind_internal_images(&kind_cluster);
    let fixture = write_single_site_kind_fixture(temp.path(), &kind_cluster);
    let storage_root = temp.path().join("state");
    let mut run = run_manifest(&fixture.manifest, &fixture.placement, &storage_root);

    let kind_state = wait_for_state_status(
        &run.run_root,
        "kind_local",
        "running",
        Duration::from_secs(120),
    );
    let first_forward_pid = kind_state["port_forward_pid"]
        .as_u64()
        .expect("kubernetes site should publish port-forward pid")
        as u32;
    let proxy_args = vec![
        "--router-addr".to_string(),
        kind_state["router_mesh_addr"]
            .as_str()
            .expect("kind router mesh addr should exist")
            .to_string(),
        "--router-control-addr".to_string(),
        kind_state["router_control"]
            .as_str()
            .expect("kind router control should exist")
            .to_string(),
    ];

    let proxy_port = pick_free_port();
    let mut proxy = spawn_proxy(
        &run.site_artifact_dir("kind_local"),
        "a_http",
        proxy_port,
        &proxy_args,
    );
    wait_for_path(proxy_port, "/id", Duration::from_secs(120));
    stop_child(&mut proxy);

    kill_pid(first_forward_pid);
    let recovered = wait_for_state_pid_change(
        &run.run_root,
        "kind_local",
        "port_forward_pid",
        first_forward_pid,
        Duration::from_secs(120),
    );
    assert_ne!(
        recovered["port_forward_pid"]
            .as_u64()
            .expect("replacement port-forward pid should exist") as u32,
        first_forward_pid
    );
    wait_for_state_status(
        &run.run_root,
        "kind_local",
        "running",
        Duration::from_secs(120),
    );

    let proxy_port = pick_free_port();
    let mut proxy = spawn_proxy(
        &run.site_artifact_dir("kind_local"),
        "a_http",
        proxy_port,
        &proxy_args,
    );
    assert_eq!(
        wait_for_body(proxy_port, "/id", Duration::from_secs(120)),
        "A"
    );
    stop_child(&mut proxy);
    run.stop();
}

#[test]
#[ignore = "requires docker; run manually or in CI"]
fn mixed_run_direct_compose_proxy_smoke() {
    ensure_internal_images();
    let temp = temp_output_dir("mixed-run-two-site-");
    let fixture = write_two_site_fixture(temp.path());

    let storage_root = temp.path().join("state");
    let mut run = run_manifest(&fixture.manifest, &fixture.placement, &storage_root);

    let run_plan: Value = serde_json::from_slice(
        &fs::read(run.run_root.join("run-plan.json")).expect("failed to read run-plan.json"),
    )
    .expect("run-plan.json should be valid JSON");
    assert_eq!(
        run_plan["startup_waves"],
        json!([["compose_local"], ["direct_local"]])
    );
    assert_eq!(
        run.receipt["sites"]
            .as_object()
            .expect("receipt sites should be an object")
            .len(),
        2
    );

    let direct_artifact = run.site_artifact_dir("direct_local");
    let proxy_port = pick_free_port();
    let mut proxy = spawn_proxy(&direct_artifact, "a_http", proxy_port, &[]);
    wait_for_path(proxy_port, "/id", Duration::from_secs(60));
    let body = wait_for_body(proxy_port, "/call/b", Duration::from_secs(60));
    assert_eq!(body, "B");
    stop_child(&mut proxy);

    run.stop();
    assert!(
        !run.run_root.join("receipt.json").exists(),
        "receipt should be removed after amber stop"
    );
}

#[test]
#[ignore = "requires docker; run manually or in CI"]
fn mixed_run_detached_stop_smoke() {
    ensure_internal_images();
    let temp = temp_output_dir("mixed-run-detach-");
    let fixture = write_two_site_fixture(temp.path());
    let storage_root = temp.path().join("state");
    let mut run = run_manifest_detached(&fixture.manifest, &fixture.placement, &storage_root);

    let direct_artifact = run.site_artifact_dir("direct_local");
    let proxy_port = pick_free_port();
    let mut proxy = spawn_proxy(&direct_artifact, "a_http", proxy_port, &[]);
    wait_for_path(proxy_port, "/id", Duration::from_secs(60));
    assert_eq!(
        wait_for_body(proxy_port, "/call/b", Duration::from_secs(60)),
        "B"
    );
    stop_child(&mut proxy);

    run.stop();
    wait_for_condition(
        Duration::from_secs(30),
        || !run.run_root.join("receipt.json").exists(),
        "detached run receipt removal",
    );
}

#[test]
#[ignore = "requires docker; run manually or in CI"]
fn mixed_run_local_observability_scenario_smoke() {
    ensure_internal_images();
    let temp = temp_output_dir("mixed-run-obsv-scenario-");
    let fixture = write_two_site_fixture(temp.path());
    let storage_root = temp.path().join("state");
    let mut run = run_manifest_with_args(
        &fixture.manifest,
        &fixture.placement,
        &storage_root,
        &["--observability", "local"],
    );

    let requests_log = PathBuf::from(
        run.receipt["observability"]["requests_log"]
            .as_str()
            .expect("run receipt should contain observability log"),
    );
    wait_for_text(&requests_log, "/v1/logs", Duration::from_secs(60));
    let before_lines = fs::read_to_string(&requests_log)
        .unwrap_or_default()
        .lines()
        .count();
    let direct_artifact = run.site_artifact_dir("direct_local");
    let proxy_port = pick_free_port();
    let mut proxy = spawn_proxy(&direct_artifact, "a_http", proxy_port, &[]);
    wait_for_path(proxy_port, "/id", Duration::from_secs(60));
    assert_eq!(
        wait_for_body(proxy_port, "/call/b", Duration::from_secs(60)),
        "B"
    );
    wait_for_condition(
        Duration::from_secs(60),
        || {
            fs::read_to_string(&requests_log)
                .map(|contents| contents.lines().count() > before_lines)
                .unwrap_or(false)
        },
        "scenario telemetry after routed traffic",
    );
    stop_child(&mut proxy);
    run.stop();
}

#[test]
#[ignore = "requires docker; run manually or in CI"]
fn mixed_run_local_observability_manager_smoke() {
    let temp = temp_output_dir("mixed-run-obsv-manager-");
    let fixture = write_single_site_direct_fixture(temp.path());
    let storage_root = temp.path().join("state");
    let mut run = run_manifest_with_args(
        &fixture.manifest,
        &fixture.placement,
        &storage_root,
        &["--observability", "local"],
    );

    let requests_log = PathBuf::from(
        run.receipt["observability"]["requests_log"]
            .as_str()
            .expect("run receipt should contain observability log"),
    );
    wait_for_text(&requests_log, "/v1/logs", Duration::from_secs(60));
    let before = fs::read_to_string(&requests_log).unwrap_or_default();
    let before_lines = before.lines().count();
    run.stop();
    wait_for_condition(
        Duration::from_secs(30),
        || {
            fs::read_to_string(&requests_log)
                .map(|contents| contents.lines().count() > before_lines)
                .unwrap_or(false)
        },
        "site-manager stop logs",
    );
}
