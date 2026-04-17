#![cfg(any(target_os = "macos", target_os = "linux"))]

#[path = "../test_support/cloud_image.rs"]
mod cloud_image_support;
#[path = "../test_support/outputs_root.rs"]
mod outputs_root_support;
#[path = "../test_support/port_allocator.rs"]
mod port_allocator_support;
#[path = "../test_support/target_dir.rs"]
mod target_dir_support;
#[path = "../test_support/workspace_root.rs"]
mod workspace_root_support;

use std::{
    collections::BTreeSet,
    env,
    ffi::OsString,
    fs,
    hash::{DefaultHasher, Hash, Hasher},
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

use amber_images::{
    AMBER_DOCKER_GATEWAY, AMBER_HELPER, AMBER_PROVISIONER, AMBER_ROUTER, AMBER_SITE_CONTROLLER,
    DEV_IMAGE_TAGS_ENV, INTERNAL_IMAGE_OVERRIDE_KEYS, ImageRef, override_reference,
    parse_dev_image_tag_overrides,
};
use cloud_image_support::default_host_arch_cloud_image_filename;
use outputs_root_support::cli_test_outputs_root;
use port_allocator_support::reserve_test_loopback_port;
use serde_json::{Value, json};
use target_dir_support::cargo_target_dir;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
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

const TEST_APP_SOURCE_IMAGE: &str = "python:3.13-alpine";
const TEST_APP_LOCAL_IMAGE_REPOSITORY: &str = "amber-mixed-run-test-app";

#[derive(Clone, Debug, PartialEq, Eq)]
struct DockerImageMeta {
    id: String,
    arch: String,
}

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

#[derive(serde::Deserialize)]
struct StaleRunReceipt {
    run_id: String,
    #[serde(default)]
    observability: Option<StaleObservabilityReceipt>,
    #[serde(default)]
    bridge_proxies: Vec<StaleBridgeProxyReceipt>,
    sites: std::collections::BTreeMap<String, StaleSiteReceipt>,
}

#[derive(serde::Deserialize)]
struct StaleObservabilityReceipt {
    #[serde(default)]
    sink_pid: Option<u32>,
}

#[derive(serde::Deserialize)]
struct StaleBridgeProxyReceipt {
    pid: u32,
}

#[derive(serde::Deserialize)]
struct StaleSiteReceipt {
    supervisor_pid: u32,
    #[serde(default)]
    process_pid: Option<u32>,
    #[serde(default)]
    port_forward_pid: Option<u32>,
    #[serde(default)]
    site_controller_pid: Option<u32>,
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
    cleanup_abandoned_test_runs_once();
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

fn cleanup_abandoned_test_runs_once() {
    static CLEANUP_ONCE: OnceLock<()> = OnceLock::new();
    CLEANUP_ONCE.get_or_init(|| {
        for entry in fs::read_dir(outputs_root())
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", outputs_root().display()))
        {
            let Ok(entry) = entry else {
                continue;
            };
            let storage_root = entry.path();
            if storage_root.is_dir() {
                cleanup_abandoned_test_runs_in_storage_root(&storage_root);
            }
        }
    });
}

fn cleanup_abandoned_test_runs_in_storage_root(storage_root: &Path) {
    let runs_dir = storage_root.join("runs");
    let Ok(entries) = fs::read_dir(&runs_dir) else {
        return;
    };
    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let run_root = entry.path();
        let receipt_path = run_root.join("receipt.json");
        if !receipt_path.is_file() {
            continue;
        }
        let Ok(receipt_bytes) = fs::read(&receipt_path) else {
            continue;
        };
        let Ok(receipt) = serde_json::from_slice::<StaleRunReceipt>(&receipt_bytes) else {
            continue;
        };
        if stale_run_has_live_processes(&receipt) {
            continue;
        }
        let _ = command_output_via_tempfiles(
            amber_command()
                .arg("stop")
                .arg(&receipt.run_id)
                .arg("--storage-root")
                .arg(storage_root),
            "amber stop stale test run",
        );
    }
}

fn stale_run_has_live_processes(receipt: &StaleRunReceipt) -> bool {
    receipt
        .observability
        .as_ref()
        .and_then(|observability| observability.sink_pid)
        .into_iter()
        .chain(receipt.bridge_proxies.iter().map(|proxy| proxy.pid))
        .chain(
            receipt
                .sites
                .values()
                .flat_map(|site| {
                    [
                        Some(site.supervisor_pid),
                        site.process_pid,
                        site.port_forward_pid,
                        site.site_controller_pid,
                    ]
                })
                .flatten(),
        )
        .any(pid_is_alive)
}

pub(crate) fn pick_free_port() -> u16 {
    reserve_test_loopback_port()
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
        .arg(test_app_image())
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

fn docker_platform_arch() -> &'static str {
    match env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        other => panic!("mixed-run tests support only aarch64 and x86_64 hosts, found {other}"),
    }
}

fn docker_platform(expected_arch: &str) -> String {
    format!("linux/{expected_arch}")
}

fn docker_image_meta_with_binaries(
    docker_bin: &Path,
    tag: &str,
) -> Result<Option<DockerImageMeta>, String> {
    let output = Command::new(docker_bin)
        .arg("image")
        .arg("inspect")
        .arg("-f")
        .arg("{{.Id}}|{{.Architecture}}")
        .arg(tag)
        .output()
        .map_err(|err| format!("failed to inspect docker image {tag}: {err}"))?;
    if !output.status.success() {
        return Ok(None);
    }
    let meta = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if meta.is_empty() {
        return Ok(None);
    }
    let (id, arch) = meta.split_once('|').ok_or_else(|| {
        format!("docker image inspect for {tag} returned malformed metadata: {meta}")
    })?;
    if id.is_empty() || arch.is_empty() {
        return Err(format!(
            "docker image inspect for {tag} returned incomplete metadata: {meta}"
        ));
    }
    Ok(Some(DockerImageMeta {
        id: id.to_string(),
        arch: arch.to_string(),
    }))
}

fn ensure_local_image_with_binaries(
    docker_bin: &Path,
    tag: &str,
    expected_arch: &str,
) -> Result<DockerImageMeta, String> {
    if let Some(meta) = docker_image_meta_with_binaries(docker_bin, tag)?
        && meta.arch == expected_arch
    {
        return Ok(meta);
    }

    let output = Command::new(docker_bin)
        .arg("pull")
        .arg("--platform")
        .arg(docker_platform(expected_arch))
        .arg(tag)
        .output()
        .map_err(|err| format!("failed to pull docker image {tag}: {err}"))?;
    if !output.status.success() {
        return Err(format_command_output(
            &format!("docker pull failed for {tag}"),
            &output,
        ));
    }

    let meta = docker_image_meta_with_binaries(docker_bin, tag)?
        .ok_or_else(|| format!("docker image {tag} is still unavailable after pull"))?;
    if meta.arch != expected_arch {
        return Err(format!(
            "docker pull resolved {tag} to linux/{} instead of {}",
            meta.arch,
            docker_platform(expected_arch)
        ));
    }
    Ok(meta)
}

fn build_test_app_image_with_binaries(
    docker_bin: &Path,
    source_image: &str,
    expected_arch: &str,
) -> Result<String, String> {
    let _ = ensure_local_image_with_binaries(docker_bin, source_image, expected_arch)?;
    let local_tag = format!("{TEST_APP_LOCAL_IMAGE_REPOSITORY}:{expected_arch}");
    let build_root = tempfile::tempdir()
        .map_err(|err| format!("failed to create temp dir for {local_tag}: {err}"))?;
    fs::write(
        build_root.path().join("Dockerfile"),
        format!("FROM {source_image}\n"),
    )
    .map_err(|err| {
        format!(
            "failed to write Dockerfile for test app image {local_tag} in {}: {err}",
            build_root.path().display()
        )
    })?;
    let output = Command::new(docker_bin)
        .arg("build")
        .arg("--platform")
        .arg(docker_platform(expected_arch))
        .arg("-t")
        .arg(&local_tag)
        .arg(build_root.path())
        .output()
        .map_err(|err| format!("failed to build docker image {local_tag}: {err}"))?;
    if !output.status.success() {
        return Err(format_command_output(
            &format!("docker build failed for {local_tag} from {source_image}"),
            &output,
        ));
    }
    Ok(local_tag)
}

pub(crate) fn test_app_image() -> &'static str {
    static IMAGE: OnceLock<String> = OnceLock::new();
    IMAGE
        .get_or_init(|| {
            build_test_app_image_with_binaries(
                Path::new("docker"),
                TEST_APP_SOURCE_IMAGE,
                docker_platform_arch(),
            )
            .unwrap_or_else(|err| panic!("{err}"))
        })
        .as_str()
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

pub(crate) fn http_get_with_timeout_result(
    port: u16,
    path: &str,
    timeout: Duration,
) -> Result<(u16, String), String> {
    http_request_with_timeout_result("GET", port, path, None, timeout)
}

pub(crate) fn http_request_with_timeout(
    method: &str,
    port: u16,
    path: &str,
    body: Option<&str>,
    timeout: Duration,
) -> Option<(u16, String)> {
    http_request_with_timeout_result(method, port, path, body, timeout).ok()
}

pub(crate) fn http_request_with_timeout_result(
    method: &str,
    port: u16,
    path: &str,
    body: Option<&str>,
    timeout: Duration,
) -> Result<(u16, String), String> {
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
    let url = format!("http://127.0.0.1:{port}{path}");
    let output = command_output_via_tempfiles(
        command
            .arg("-o")
            .arg("-")
            .arg("-w")
            .arg("\n%{http_code}")
            .arg(&url),
        "curl http request",
    );
    if !output.status.success() {
        return Err(format_command_output(
            &format!(
                "curl {method} {url} failed after {:.3}s",
                timeout.as_secs_f64()
            ),
            &output,
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let Some((body, status)) = stdout.rsplit_once('\n') else {
        return Err(format!(
            "curl {method} {url} returned a malformed response after \
             {:.3}s\nstdout:\n{}\nstderr:\n{}",
            timeout.as_secs_f64(),
            stdout,
            String::from_utf8_lossy(&output.stderr),
        ));
    };
    let status = status.trim().parse().map_err(|err| {
        format!(
            "curl {method} {url} returned a malformed HTTP status `{}` after {:.3}s: \
             {err}\nstdout:\n{}\nstderr:\n{}",
            status.trim(),
            timeout.as_secs_f64(),
            stdout,
            String::from_utf8_lossy(&output.stderr),
        )
    })?;
    Ok((status, body.trim().to_string()))
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

fn manager_state_value(state_path: &Path) -> Option<Value> {
    fs::read_to_string(state_path)
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
}

fn append_docker_project_debug(out: &mut String, project: &str) {
    let project_filter = format!("label=com.docker.compose.project={project}");
    let ps_output = match Command::new("docker")
        .args([
            "ps",
            "-a",
            "--filter",
            project_filter.as_str(),
            "--format",
            "{{.ID}}\t{{.Names}}\t{{.Status}}",
        ])
        .output()
    {
        Ok(output) => output,
        Err(err) => {
            out.push_str(&format!(
                "\ndocker compose project `{project}` status query failed:\n{err}\n"
            ));
            return;
        }
    };

    if !ps_output.status.success() {
        out.push_str(&format!(
            "\ndocker compose project `{project}` status query failed\nstdout:\n{}\nstderr:\n{}\n",
            String::from_utf8_lossy(&ps_output.stdout),
            String::from_utf8_lossy(&ps_output.stderr),
        ));
        return;
    }

    let containers = String::from_utf8_lossy(&ps_output.stdout)
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(3, '\t');
            Some((
                parts.next()?.trim().to_string(),
                parts.next()?.trim().to_string(),
                parts.next()?.trim().to_string(),
            ))
        })
        .collect::<Vec<_>>();

    if containers.is_empty() {
        out.push_str(&format!(
            "\ndocker compose project `{project}` containers:\n<none>\n"
        ));
        return;
    }

    out.push_str(&format!(
        "\ndocker compose project `{project}` containers:\n"
    ));
    for (_, name, status) in &containers {
        out.push_str(&format!("{name}\t{status}\n"));
    }

    for (id, name, status) in containers {
        let logs_output = match Command::new("docker")
            .args(["logs", "--tail", "80", id.as_str()])
            .output()
        {
            Ok(output) => output,
            Err(err) => {
                out.push_str(&format!("\ndocker logs {name} ({status}) failed:\n{err}\n"));
                continue;
            }
        };
        out.push_str(&format!(
            "\ndocker logs {name} ({status}):\nstdout:\n{}\nstderr:\n{}\n",
            String::from_utf8_lossy(&logs_output.stdout),
            String::from_utf8_lossy(&logs_output.stderr),
        ));
    }
}

pub(crate) fn site_debug_context(run_root: &Path, site_id: &str) -> String {
    let state_root = run_root.join("state").join(site_id);
    let manager_state_path = state_root.join("manager-state.json");
    let mut out = String::new();
    append_debug_file(&mut out, "manager state", &manager_state_path);
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
    if let Some(project) = manager_state_value(&manager_state_path)
        .and_then(|state| state["compose_project"].as_str().map(ToOwned::to_owned))
    {
        append_docker_project_debug(&mut out, &project);
    }
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
    ensure_local_dev_image_tag_overrides();
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

fn internal_image_build_mode() -> &'static str {
    static MODE: OnceLock<&'static str> = OnceLock::new();
    MODE.get_or_init(|| match env::var("AMBER_TEST_INTERNAL_IMAGE_BUILD_MODE") {
        Ok(mode) if mode == "release" => "release",
        Ok(mode) if mode == "debug" => "debug",
        Ok(mode) => panic!(
            "AMBER_TEST_INTERNAL_IMAGE_BUILD_MODE must be `debug` or `release`, got `{mode}`"
        ),
        Err(env::VarError::NotPresent) => "debug",
        Err(env::VarError::NotUnicode(value)) => panic!(
            "AMBER_TEST_INTERNAL_IMAGE_BUILD_MODE must be valid UTF-8, got {:?}",
            value
        ),
    })
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

    if docker_image_is_fresh(tag, dockerfile) {
        return;
    }

    let mut last_status = None;
    for attempt in 1..=3 {
        let mut command = Command::new("docker");
        if docker_supports_buildx() {
            command
                .arg("buildx")
                .arg("build")
                .arg("--load")
                .arg("--progress")
                .arg("plain");
        } else {
            command.env("DOCKER_BUILDKIT", "1");
            command.arg("build");
        }
        let status = command
            .arg("--build-arg")
            .arg(format!("BUILD_MODE={}", internal_image_build_mode()))
            .arg("-t")
            .arg(tag)
            .arg("-f")
            .arg(dockerfile)
            .arg(workspace_root())
            .status()
            .unwrap_or_else(|err| panic!("failed to build {tag}: {err}"));
        if status.success() {
            return;
        }
        last_status = Some(status);
        if attempt < 3 {
            eprintln!("docker build attempt {attempt} failed for {tag}; retrying");
            thread::sleep(Duration::from_secs(attempt * 2));
        }
    }
    let status = last_status.expect("docker build should have produced a status");
    panic!("docker build failed for {tag} after retries with status {status}");
}

fn docker_image_is_fresh(tag: &str, dockerfile: &Path) -> bool {
    if image_platform_opt(tag).is_none() {
        return false;
    }
    let Some(image_created) = docker_image_created_at(tag) else {
        return false;
    };
    !source_is_newer_than_image(
        image_created,
        newest_internal_image_input_mtime(&workspace_root(), dockerfile),
    )
}

fn docker_image_created_at(tag: &str) -> Option<SystemTime> {
    let output = Command::new("docker")
        .arg("image")
        .arg("inspect")
        .arg("-f")
        .arg("{{.Created}}")
        .arg(tag)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let created = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let timestamp = OffsetDateTime::parse(&created, &Rfc3339).ok()?;
    Some(UNIX_EPOCH + Duration::from_secs(timestamp.unix_timestamp() as u64))
}

fn newest_internal_image_input_mtime(
    workspace_root: &Path,
    dockerfile: &Path,
) -> Option<SystemTime> {
    [
        workspace_root.join("Cargo.toml"),
        workspace_root.join("Cargo.lock"),
        workspace_root.join("rust-toolchain.toml"),
        workspace_root.join("cli"),
        workspace_root.join("compiler"),
        workspace_root.join("images"),
        workspace_root.join("runtime"),
        dockerfile.to_path_buf(),
    ]
    .into_iter()
    .filter_map(|path| newest_path_mtime(&path))
    .max()
}

fn newest_path_mtime(path: &Path) -> Option<SystemTime> {
    let metadata = fs::metadata(path).ok()?;
    if metadata.is_file() {
        return metadata.modified().ok();
    }
    if !metadata.is_dir() {
        return None;
    }

    let mut newest = metadata.modified().ok();
    let entries = fs::read_dir(path).ok()?;
    for entry in entries.filter_map(Result::ok) {
        let child = entry.path();
        let child_name = child
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if child_name == "target" || child_name == ".git" {
            continue;
        }
        if let Some(child_mtime) = newest_path_mtime(&child) {
            newest = match newest {
                Some(current) if current >= child_mtime => Some(current),
                _ => Some(child_mtime),
            };
        }
    }
    newest
}

fn source_is_newer_than_image(
    image_created: SystemTime,
    newest_source: Option<SystemTime>,
) -> bool {
    newest_source.is_some_and(|source| source > image_created)
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

pub(crate) fn ensure_amber_internal_images() {
    static READY: OnceLock<()> = OnceLock::new();
    READY.get_or_init(|| {
        ensure_local_dev_image_tag_overrides();
        let root = workspace_root();
        let images = amber_internal_image_refs();
        ensure_docker_image(&images.router, &root.join("docker/amber-router/Dockerfile"));
        ensure_docker_image(
            &images.provisioner,
            &root.join("docker/amber-provisioner/Dockerfile"),
        );
        ensure_docker_image(&images.helper, &root.join("docker/amber-helper/Dockerfile"));
        ensure_docker_image(
            &images.site_controller,
            &root.join("docker/amber-site-controller/Dockerfile"),
        );
        ensure_docker_image(
            &images.docker_gateway,
            &root.join("docker/amber-docker-gateway/Dockerfile"),
        );
    });
}

pub(crate) fn ensure_internal_images() {
    static READY: OnceLock<()> = OnceLock::new();
    READY.get_or_init(|| {
        let _ = test_app_image();
        ensure_amber_internal_images();
    });
}

#[derive(Clone)]
struct AmberInternalImageRefs {
    router: String,
    helper: String,
    provisioner: String,
    docker_gateway: String,
    site_controller: String,
}

fn amber_internal_image_refs() -> AmberInternalImageRefs {
    let overrides = parse_dev_image_tag_overrides(INTERNAL_IMAGE_OVERRIDE_KEYS)
        .unwrap_or_else(|err| panic!("invalid {DEV_IMAGE_TAGS_ENV}: {err}"));
    let resolve = |image: &ImageRef, key: &str| {
        overrides
            .get(key)
            .map(|tag| override_reference(image, tag))
            .unwrap_or_else(|| image.reference.to_string())
    };
    AmberInternalImageRefs {
        router: resolve(&AMBER_ROUTER, "router"),
        helper: resolve(&AMBER_HELPER, "helper"),
        provisioner: resolve(&AMBER_PROVISIONER, "provisioner"),
        docker_gateway: resolve(&AMBER_DOCKER_GATEWAY, "docker_gateway"),
        site_controller: resolve(&AMBER_SITE_CONTROLLER, "site_controller"),
    }
}

fn ensure_local_dev_image_tag_overrides() {
    static READY: OnceLock<()> = OnceLock::new();
    READY.get_or_init(|| {
        if use_prebuilt_images()
            || env::var_os("CI").is_some()
            || env::var_os(DEV_IMAGE_TAGS_ENV).is_some()
        {
            return;
        }
        let mut hasher = DefaultHasher::new();
        workspace_root().hash(&mut hasher);
        internal_image_build_mode().hash(&mut hasher);
        let tag = format!(
            "dev-mixed-run-{}-{:016x}",
            internal_image_build_mode(),
            hasher.finish()
        );
        let overrides = INTERNAL_IMAGE_OVERRIDE_KEYS
            .iter()
            .map(|key| format!("{key}={tag}"))
            .collect::<Vec<_>>()
            .join(",");
        unsafe {
            env::set_var(DEV_IMAGE_TAGS_ENV, overrides);
        }
    });
}

pub(crate) fn load_kind_image(cluster_name: &str, image: &str) {
    load_kind_image_with_binaries(Path::new("kind"), Path::new("docker"), cluster_name, image)
        .unwrap_or_else(|err| panic!("{err}"));
}

fn load_kind_image_with_binaries(
    kind_bin: &Path,
    docker_bin: &Path,
    cluster_name: &str,
    image: &str,
) -> Result<(), String> {
    let mut direct_error = None;
    for attempt in 1..=3 {
        match kind_load_docker_image(kind_bin, cluster_name, image) {
            Ok(()) => return Ok(()),
            Err(err) => {
                direct_error = Some(err);
                if attempt < 3 {
                    eprintln!(
                        "kind load docker-image attempt {attempt} failed for {image} in cluster \
                         {cluster_name}; retrying"
                    );
                    thread::sleep(Duration::from_secs(attempt * 2));
                }
            }
        }
    }

    let direct_error = direct_error.expect("kind image load should record a failure");
    let archive = tempfile::Builder::new()
        .prefix("amber-kind-image-")
        .suffix(".tar")
        .tempfile()
        .map_err(|err| {
            format!("failed to create temporary image archive for {image} in {cluster_name}: {err}")
        })?;
    kind_load_image_archive_with_binaries(kind_bin, docker_bin, cluster_name, image, archive)
        .map_err(|archive_error| {
            format!(
                "{direct_error}

kind load image-archive fallback failed for {image} in cluster {cluster_name}:
{archive_error}"
            )
        })
}

fn kind_load_docker_image(kind_bin: &Path, cluster_name: &str, image: &str) -> Result<(), String> {
    let output = Command::new(kind_bin)
        .arg("load")
        .arg("docker-image")
        .arg("--name")
        .arg(cluster_name)
        .arg(image)
        .output()
        .map_err(|err| {
            format!("failed to run `kind load docker-image` for {image} in {cluster_name}: {err}")
        })?;
    if output.status.success() {
        return Ok(());
    }
    Err(format_command_output(
        &format!("kind load docker-image failed for {image} in cluster {cluster_name}"),
        &output,
    ))
}

fn kind_load_image_archive_with_binaries(
    kind_bin: &Path,
    docker_bin: &Path,
    cluster_name: &str,
    image: &str,
    archive: tempfile::NamedTempFile,
) -> Result<(), String> {
    let archive_path = archive.path().to_path_buf();
    let docker_output = Command::new(docker_bin)
        .arg("image")
        .arg("save")
        .arg("--output")
        .arg(&archive_path)
        .arg(image)
        .output()
        .map_err(|err| {
            format!("failed to run `docker image save` for {image} in {cluster_name}: {err}")
        })?;
    if !docker_output.status.success() {
        return Err(format_command_output(
            &format!("docker image save failed for {image}"),
            &docker_output,
        ));
    }

    let kind = Command::new(kind_bin)
        .arg("load")
        .arg("image-archive")
        .arg("--name")
        .arg(cluster_name)
        .arg(&archive_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|err| {
            format!(
                "failed to run `kind load image-archive` fallback for {image} in {cluster_name}: \
                 {err}"
            )
        })?;
    if kind.status.success() {
        return Ok(());
    }

    Err(format_command_output(
        &format!("kind load image-archive failed for {image} in cluster {cluster_name}"),
        &kind,
    ))
}

fn format_command_output(label: &str, output: &std::process::Output) -> String {
    format!(
        "{label} with status {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

pub(crate) fn ensure_kind_internal_images(kind_cluster: &KindCluster) {
    ensure_internal_images();
    static READY: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
    let name = kind_cluster.name.clone();
    let images = amber_internal_image_refs();
    let ready_key = format!(
        "{name}|{}|{}|{}|{}|{}",
        images.router,
        images.provisioner,
        images.helper,
        images.site_controller,
        test_app_image()
    );
    let loaded = READY.get_or_init(|| Mutex::new(BTreeSet::new()));
    {
        let loaded = loaded.lock().expect("kind image-load guard should lock");
        if loaded.contains(&ready_key) {
            return;
        }
    }
    load_kind_image(&name, &images.router);
    load_kind_image(&name, &images.provisioner);
    load_kind_image(&name, &images.helper);
    load_kind_image(&name, &images.site_controller);
    load_kind_image(&name, test_app_image());
    loaded
        .lock()
        .expect("kind image-load guard should lock")
        .insert(ready_key);
}

pub(crate) fn kill_pid(pid: u32) {
    #[cfg(unix)]
    unsafe {
        let _ = libc::kill(pid as i32, libc::SIGTERM);
    }
}

pub(crate) fn framework_child_artifact_dir(
    run_root: &Path,
    site_id: &str,
    child_id: u64,
) -> PathBuf {
    let manager_state = site_manager_state(run_root, site_id);
    if manager_state["kind"].as_str() == Some("kubernetes") {
        let artifact_dir =
            framework_child_kubernetes_cache_artifact_dir(run_root, site_id, child_id);
        materialize_kubernetes_child_artifact(&manager_state, child_id, &artifact_dir);
        return artifact_dir;
    }

    framework_child_host_artifact_dir(run_root, site_id, child_id)
}

pub(crate) fn framework_control_state_snapshot(control_state_root: &Path) -> Value {
    let mut live_children = Vec::new();
    let entries = fs::read_dir(control_state_root)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", control_state_root.display()));
    for entry in entries.filter_map(Result::ok) {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let Some(site_id) = entry.file_name().into_string().ok() else {
            continue;
        };
        let state = framework_site_control_state(control_state_root, &site_id);
        if let Some(children) = state["live_children"].as_array() {
            live_children.extend(children.iter().cloned());
        }
    }
    json!({ "live_children": live_children })
}

pub(crate) fn framework_child_is_absent(run_root: &Path, site_id: &str, child_id: u64) -> bool {
    let manager_state = site_manager_state(run_root, site_id);
    if manager_state["kind"].as_str() != Some("kubernetes") {
        return !framework_child_host_child_root(run_root, site_id, child_id).exists();
    }

    if kubernetes_child_runtime_root_exists(&manager_state, child_id) {
        return false;
    }

    let cache_root = framework_child_kubernetes_cache_child_root(run_root, site_id, child_id);
    if cache_root.exists() {
        fs::remove_dir_all(&cache_root).unwrap_or_else(|err| {
            panic!(
                "failed to clear stale kubernetes child cache {}: {err}",
                cache_root.display()
            )
        });
    }
    true
}

fn framework_site_control_state(control_state_root: &Path, site_id: &str) -> Value {
    let manager_state = site_manager_state_from_state_root(control_state_root, site_id);
    let state_path = framework_site_control_state_path(control_state_root, site_id, &manager_state);
    if manager_state["kind"].as_str() == Some("kubernetes") {
        materialize_kubernetes_control_state(&manager_state, &state_path);
    }
    read_json(&state_path)
}

fn site_manager_state(run_root: &Path, site_id: &str) -> Value {
    site_manager_state_from_state_root(&run_root.join("state"), site_id)
}

fn site_manager_state_from_state_root(state_root: &Path, site_id: &str) -> Value {
    let manager_state_path = state_root.join(site_id).join("manager-state.json");
    serde_json::from_slice(&fs::read(&manager_state_path).unwrap_or_else(|err| {
        panic!(
            "failed to read site manager state {}: {err}",
            manager_state_path.display()
        )
    }))
    .unwrap_or_else(|err| {
        panic!(
            "failed to parse site manager state {}: {err}",
            manager_state_path.display()
        )
    })
}

fn framework_site_control_state_path(
    control_state_root: &Path,
    site_id: &str,
    manager_state: &Value,
) -> PathBuf {
    if manager_state["kind"].as_str() == Some("kubernetes") {
        return framework_kubernetes_cache_control_state_path(control_state_root, site_id);
    }
    control_state_root
        .join(site_id)
        .join("site-controller-state.json")
}

fn framework_kubernetes_cache_control_state_path(
    control_state_root: &Path,
    site_id: &str,
) -> PathBuf {
    control_state_root
        .join(site_id)
        .join("framework-component-kubernetes-cache")
        .join("site-controller-state.json")
}

fn framework_child_host_child_root(run_root: &Path, site_id: &str, child_id: u64) -> PathBuf {
    run_root
        .join("state")
        .join(site_id)
        .join("framework-component")
        .join("children")
        .join(child_id.to_string())
}

fn framework_child_host_artifact_dir(run_root: &Path, site_id: &str, child_id: u64) -> PathBuf {
    framework_child_host_child_root(run_root, site_id, child_id).join("artifact")
}

fn framework_child_kubernetes_cache_child_root(
    run_root: &Path,
    site_id: &str,
    child_id: u64,
) -> PathBuf {
    run_root
        .join("state")
        .join(site_id)
        .join("framework-component-kubernetes-cache")
        .join("children")
        .join(child_id.to_string())
}

fn framework_child_kubernetes_cache_artifact_dir(
    run_root: &Path,
    site_id: &str,
    child_id: u64,
) -> PathBuf {
    framework_child_kubernetes_cache_child_root(run_root, site_id, child_id).join("artifact")
}

fn kubernetes_child_runtime_root_exists(manager_state: &Value, child_id: u64) -> bool {
    let namespace = manager_state["kubernetes_namespace"]
        .as_str()
        .unwrap_or_else(|| panic!("kubernetes manager state is missing kubernetes_namespace"));
    let pod = kubernetes_site_controller_pod_name(manager_state, namespace);
    let remote_child_root = format!("/amber/site/state/framework-component/children/{child_id}");
    let output = kubectl_for_manager_state(manager_state)
        .arg("-n")
        .arg(namespace)
        .arg("exec")
        .arg(&pod)
        .arg("--")
        .arg("sh")
        .arg("-lc")
        .arg(format!("test -d {remote_child_root}"))
        .output()
        .unwrap_or_else(|err| {
            panic!(
                "failed to probe kubernetes child runtime root {remote_child_root} in {pod}: {err}"
            )
        });
    match output.status.code() {
        Some(0) => true,
        Some(1) => false,
        _ => {
            panic!(
                "failed to probe kubernetes child runtime root {remote_child_root} in {pod}: {}",
                String::from_utf8_lossy(&output.stderr)
            )
        }
    }
}

fn materialize_kubernetes_child_artifact(
    manager_state: &Value,
    child_id: u64,
    artifact_dir: &Path,
) {
    if artifact_dir.is_dir() {
        return;
    }
    let namespace = manager_state["kubernetes_namespace"]
        .as_str()
        .unwrap_or_else(|| panic!("kubernetes manager state is missing kubernetes_namespace"));
    let pod = kubernetes_site_controller_pod_name(manager_state, namespace);
    let remote_artifact_dir =
        format!("/amber/site/state/framework-component/children/{child_id}/artifact");
    let parent = artifact_dir.parent().unwrap_or_else(|| {
        panic!(
            "artifact dir {} should have a parent",
            artifact_dir.display()
        )
    });
    fs::create_dir_all(parent).unwrap_or_else(|err| {
        panic!(
            "failed to create framework child parent {}: {err}",
            parent.display()
        )
    });
    let target = parent.join(format!("artifact-kubernetes-copy-{child_id}"));
    if target.exists() {
        fs::remove_dir_all(&target).unwrap_or_else(|err| {
            panic!(
                "failed to clear previous kubernetes child artifact copy {}: {err}",
                target.display()
            )
        });
    }
    let mut command = kubectl_for_manager_state(manager_state);
    let status = command
        .arg("-n")
        .arg(namespace)
        .arg("cp")
        .arg(format!("{pod}:{remote_artifact_dir}"))
        .arg(&target)
        .status()
        .unwrap_or_else(|err| {
            panic!(
                "failed to copy kubernetes child artifact {remote_artifact_dir} from {pod}: {err}"
            )
        });
    if !status.success() {
        panic!(
            "kubectl cp failed for kubernetes child artifact {remote_artifact_dir} from {pod} \
             with status {status}"
        );
    }
    fs::rename(&target, artifact_dir).unwrap_or_else(|err| {
        panic!(
            "failed to move kubernetes child artifact copy {} into {}: {err}",
            target.display(),
            artifact_dir.display()
        )
    });
}

fn materialize_kubernetes_control_state(manager_state: &Value, state_path: &Path) {
    let namespace = manager_state["kubernetes_namespace"]
        .as_str()
        .unwrap_or_else(|| panic!("kubernetes manager state is missing kubernetes_namespace"));
    let pod = kubernetes_site_controller_pod_name(manager_state, namespace);
    let parent = state_path.parent().unwrap_or_else(|| {
        panic!(
            "framework control state path {} should have a parent",
            state_path.display()
        )
    });
    fs::create_dir_all(parent).unwrap_or_else(|err| {
        panic!(
            "failed to create kubernetes control state cache parent {}: {err}",
            parent.display()
        )
    });
    let target = parent.join("site-controller-state-kubernetes-copy.json");
    let output = kubectl_for_manager_state(manager_state)
        .arg("-n")
        .arg(namespace)
        .arg("exec")
        .arg(&pod)
        .arg("--")
        .arg("cat")
        .arg("/amber/site/state/site-controller-state.json")
        .output()
        .unwrap_or_else(|err| {
            panic!("failed to read kubernetes control state from {pod} in {namespace}: {err}")
        });
    if !output.status.success() {
        panic!(
            "failed to read kubernetes control state from {pod} in {namespace}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    fs::write(&target, &output.stdout).unwrap_or_else(|err| {
        panic!(
            "failed to write temporary kubernetes control state cache {}: {err}",
            target.display()
        )
    });
    fs::rename(&target, state_path).unwrap_or_else(|err| {
        panic!(
            "failed to move kubernetes control state cache {} into {}: {err}",
            target.display(),
            state_path.display()
        )
    });
}

fn kubernetes_site_controller_pod_name(manager_state: &Value, namespace: &str) -> String {
    let mut command = kubectl_for_manager_state(manager_state);
    let output = command
        .arg("-n")
        .arg(namespace)
        .arg("get")
        .arg("pods")
        .arg("-l")
        .arg("amber.io/component=amber-site-controller")
        .arg("-o")
        .arg("jsonpath={.items[0].metadata.name}")
        .output()
        .unwrap_or_else(|err| {
            panic!("failed to query kubernetes site-controller pod in {namespace}: {err}")
        });
    if !output.status.success() {
        panic!(
            "failed to query kubernetes site-controller pod in {namespace}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let pod = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if pod.is_empty() {
        panic!("kubernetes site-controller pod is missing in namespace {namespace}");
    }
    pod
}

fn kubectl_for_manager_state(manager_state: &Value) -> Command {
    let mut command = Command::new("kubectl");
    if let Some(kubeconfig) = env::var_os("AMBER_TEST_KIND_KUBECONFIG") {
        command.env("KUBECONFIG", kubeconfig);
    }
    if let Some(context) = manager_state["context"].as_str() {
        command.arg("--context").arg(context);
    }
    command
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
        let output = command_output_via_tempfiles(
            amber_command()
                .arg("stop")
                .arg(&self.run_id)
                .arg("--storage-root")
                .arg(&self.storage_root)
                .envs(self.command_env.iter().map(|(key, value)| (key, value))),
            "amber stop",
        );
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
        let _ = command_output_via_tempfiles(
            amber_command()
                .arg("stop")
                .arg(&self.run_id)
                .arg("--storage-root")
                .arg(&self.storage_root)
                .envs(self.command_env.iter().map(|(key, value)| (key, value))),
            "amber stop",
        );
        self.stopped = true;
    }
}

pub(crate) fn command_output_via_tempfiles(
    command: &mut Command,
    label: &str,
) -> std::process::Output {
    let stdout_file = tempfile::NamedTempFile::new()
        .unwrap_or_else(|err| panic!("failed to create stdout temp file for {label}: {err}"));
    let stderr_file = tempfile::NamedTempFile::new()
        .unwrap_or_else(|err| panic!("failed to create stderr temp file for {label}: {err}"));
    let status = command
        .stdout(Stdio::from(stdout_file.reopen().unwrap_or_else(|err| {
            panic!("failed to reopen stdout temp file for {label}: {err}")
        })))
        .stderr(Stdio::from(stderr_file.reopen().unwrap_or_else(|err| {
            panic!("failed to reopen stderr temp file for {label}: {err}")
        })))
        .status()
        .unwrap_or_else(|err| panic!("failed to run {label}: {err}"));
    let stdout = fs::read(stdout_file.path())
        .unwrap_or_else(|err| panic!("failed to read stdout temp file for {label}: {err}"));
    let stderr = fs::read(stderr_file.path())
        .unwrap_or_else(|err| panic!("failed to read stderr temp file for {label}: {err}"));
    std::process::Output {
        status,
        stdout,
        stderr,
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
    let output = command_output_via_tempfiles(
        amber_command()
            .arg("run")
            .arg(manifest)
            .arg("--placement")
            .arg(placement)
            .arg("--storage-root")
            .arg(storage_root)
            .args(extra_args)
            .envs(extra_env.iter().copied()),
        "amber run",
    );
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
    let output = command_output_via_tempfiles(&mut cmd, "amber run");
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
    command_output_via_tempfiles(
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
            .arg(bundle_root),
        "amber run --dry-run",
    )
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
                "image": test_app_image(),
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
    previous_cluster_name: Option<OsString>,
    previous_kubeconfig: Option<OsString>,
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
        let previous_cluster_name = env::var_os("AMBER_TEST_KIND_CLUSTER_NAME");
        let previous_kubeconfig = env::var_os("AMBER_TEST_KIND_KUBECONFIG");
        unsafe {
            env::set_var("AMBER_TEST_KIND_CLUSTER_NAME", &name);
            env::set_var("AMBER_TEST_KIND_KUBECONFIG", kubeconfig);
        }
        Self {
            name,
            kubeconfig: kubeconfig.to_path_buf(),
            previous_cluster_name,
            previous_kubeconfig,
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
        unsafe {
            match &self.previous_cluster_name {
                Some(value) => env::set_var("AMBER_TEST_KIND_CLUSTER_NAME", value),
                None => env::remove_var("AMBER_TEST_KIND_CLUSTER_NAME"),
            }
            match &self.previous_kubeconfig {
                Some(value) => env::set_var("AMBER_TEST_KIND_KUBECONFIG", value),
                None => env::remove_var("AMBER_TEST_KIND_KUBECONFIG"),
            }
        }
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

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    #[test]
    fn command_output_via_tempfiles_does_not_wait_for_background_stdout_writer() {
        let started = Instant::now();
        let output = command_output_via_tempfiles(
            Command::new("sh").arg("-c").arg("(sleep 2) & printf done"),
            "background stdout writer",
        );
        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout), "done");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "capturing to temp files should wait for the command, not background writers"
        );
    }

    #[test]
    fn source_is_newer_than_image_detects_newer_sources() {
        let image_created = UNIX_EPOCH + Duration::from_secs(10);
        let newest_source = Some(UNIX_EPOCH + Duration::from_secs(11));
        assert!(source_is_newer_than_image(image_created, newest_source));
    }

    #[test]
    fn source_is_newer_than_image_ignores_older_or_missing_sources() {
        let image_created = UNIX_EPOCH + Duration::from_secs(10);
        assert!(!source_is_newer_than_image(
            image_created,
            Some(UNIX_EPOCH + Duration::from_secs(9))
        ));
        assert!(!source_is_newer_than_image(image_created, None));
    }

    #[test]
    fn framework_child_artifact_dir_uses_dedicated_kubernetes_cache() {
        let temp = tempfile::tempdir().expect("tempdir should create");
        let manager_state_path = temp
            .path()
            .join("state")
            .join("kind_local")
            .join("manager-state.json");
        fs::create_dir_all(manager_state_path.parent().expect("manager state parent"))
            .expect("manager state dir should create");
        fs::write(
            &manager_state_path,
            serde_json::to_vec(&json!({
                "kind": "kubernetes",
                "kubernetes_namespace": "amber-test",
            }))
            .expect("manager state should serialize"),
        )
        .expect("manager state should write");

        let cache_dir = framework_child_kubernetes_cache_artifact_dir(temp.path(), "kind_local", 7);
        fs::create_dir_all(&cache_dir).expect("kubernetes cache dir should exist");

        let artifact_dir = framework_child_artifact_dir(temp.path(), "kind_local", 7);
        assert_eq!(artifact_dir, cache_dir);
        assert!(
            !artifact_dir.starts_with(
                temp.path()
                    .join("state")
                    .join("kind_local")
                    .join("framework-component")
                    .join("children")
            ),
            "kubernetes child artifact inspection should not reuse the authoritative host state \
             path"
        );
    }

    #[test]
    fn framework_control_state_path_uses_dedicated_kubernetes_cache() {
        let state_root = Path::new("/tmp/amber-run/state");
        let manager_state = json!({
            "kind": "kubernetes",
            "kubernetes_namespace": "amber-test",
        });

        let state_path =
            framework_site_control_state_path(state_root, "kind_local", &manager_state);
        assert_eq!(
            state_path,
            framework_kubernetes_cache_control_state_path(state_root, "kind_local")
        );
        assert!(
            !state_path.ends_with("site-controller-state.json")
                || state_path
                    .parent()
                    .and_then(Path::file_name)
                    .is_some_and(|name| name == "framework-component-kubernetes-cache"),
            "kubernetes framework control state should use the dedicated cache path, got {}",
            state_path.display()
        );
    }

    #[cfg(unix)]
    #[test]
    fn kind_load_image_archive_uses_real_archive_path() {
        let temp = tempfile::tempdir().expect("tempdir should create");
        let docker = temp.path().join("docker");
        let kind = temp.path().join("kind");
        let log_path = temp.path().join("commands.log");

        fs::write(
            &docker,
            format!(
                "#!/bin/sh\nset -eu\nprintf 'docker %s\\n' \"$*\" >> '{}'\nif [ \"$1\" = image ] \
                 && [ \"$2\" = inspect ] && [ \"$3\" = -f ] && [ \"$4\" = \
                 '{{{{.Id}}}}|{{{{.Architecture}}}}' ] && [ \"$5\" = 'test:image' ]; then\n  exit \
                 1\nfi\nif [ \"$1\" = image ] && [ \"$2\" = save ] && [ \"$3\" = --output ]; \
                 then\n  printf 'archive' > \"$4\"\n  exit 0\nfi\necho \"unexpected docker \
                 invocation: $*\" >&2\nexit 1\n",
                log_path.display()
            ),
        )
        .expect("docker stub should write");
        fs::write(
            &kind,
            format!(
                "#!/bin/sh\nset -eu\nprintf 'kind %s\\n' \"$*\" >> '{}'\narchive=\"${{5:-}}\"\nif \
                 [ \"$1\" = load ] && [ \"$2\" = image-archive ] && [ \"$3\" = --name ] && [ \
                 \"$5\" != '-' ] && [ -f \"$archive\" ]; then\n  exit 0\nfi\necho \"unexpected \
                 kind invocation: $*\" >&2\nexit 1\n",
                log_path.display()
            ),
        )
        .expect("kind stub should write");
        for path in [&docker, &kind] {
            let mut permissions = fs::metadata(path)
                .expect("stub metadata should read")
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(path, permissions).expect("stub should chmod");
        }

        let archive = tempfile::Builder::new()
            .prefix("kind-archive-")
            .suffix(".tar")
            .tempfile_in(temp.path())
            .expect("temp archive should create");
        kind_load_image_archive_with_binaries(
            &kind,
            &docker,
            "test-cluster",
            "test:image",
            archive,
        )
        .expect("kind image-archive fallback should use a real archive path");

        let log = fs::read_to_string(&log_path).expect("commands log should read");
        assert!(
            log.lines()
                .any(|line| line.contains("docker image save --output ")),
            "docker should save to a concrete archive path:\n{log}"
        );
        assert!(
            log.lines().any(|line| {
                line.starts_with("kind load image-archive --name test-cluster ")
                    && !line.ends_with(" -")
            }),
            "kind should receive the archive filename, not stdin:\n{log}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn kind_load_image_archive_saves_the_requested_image_tag() {
        let temp = tempfile::tempdir().expect("tempdir should create");
        let docker = temp.path().join("docker");
        let kind = temp.path().join("kind");
        let log_path = temp.path().join("commands.log");

        fs::write(
            &docker,
            format!(
                r#"#!/bin/sh
set -eu
printf 'docker %s
' "$*" >> '{}'
if [ "$1" = image ] && [ "$2" = save ] && [ "$3" = --output ] && [ "$5" = 'test:image' ]; then
  printf 'archive' > "$4"
  exit 0
fi
echo "unexpected docker invocation: $*" >&2
exit 1
"#,
                log_path.display()
            ),
        )
        .expect("docker stub should write");
        fs::write(
            &kind,
            format!(
                r#"#!/bin/sh
set -eu
printf 'kind %s
' "$*" >> '{}'
archive="${{5:-}}"
if [ "$1" = load ] && [ "$2" = image-archive ] && [ "$3" = --name ] && [ -f "$archive" ]; then
  exit 0
fi
echo "unexpected kind invocation: $*" >&2
exit 1
"#,
                log_path.display()
            ),
        )
        .expect("kind stub should write");
        for path in [&docker, &kind] {
            let mut permissions = fs::metadata(path)
                .expect("stub metadata should read")
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(path, permissions).expect("stub should chmod");
        }

        let archive = tempfile::Builder::new()
            .prefix("kind-archive-")
            .suffix(".tar")
            .tempfile_in(temp.path())
            .expect("temp archive should create");
        kind_load_image_archive_with_binaries(
            &kind,
            &docker,
            "test-cluster",
            "test:image",
            archive,
        )
        .expect("kind image-archive fallback should save the requested image tag");

        let log = fs::read_to_string(&log_path).expect("commands log should read");
        assert!(
            log.lines().any(|line| {
                line.contains("docker image save --output ") && line.ends_with(" test:image")
            }),
            "docker save should export the requested image tag:
{log}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_kind_image_retries_direct_load_before_single_archive_fallback() {
        let temp = tempfile::tempdir().expect("tempdir should create");
        let docker = temp.path().join("docker");
        let kind = temp.path().join("kind");
        let log_path = temp.path().join("commands.log");

        fs::write(
            &docker,
            format!(
                r#"#!/bin/sh
set -eu
printf 'docker %s
' "$*" >> '{}'
if [ "$1" = image ] && [ "$2" = save ] && [ "$3" = --output ] && [ "$5" = 'test:image' ]; then
  printf 'archive' > "$4"
  exit 0
fi
echo "unexpected docker invocation: $*" >&2
exit 1
"#,
                log_path.display()
            ),
        )
        .expect("docker stub should write");
        fs::write(
            &kind,
            format!(
                r#"#!/bin/sh
set -eu
printf 'kind %s
' "$*" >> '{}'
archive="${{5:-}}"
if [ "$1" = load ] && [ "$2" = docker-image ]; then
  exit 1
fi
if [ "$1" = load ] && [ "$2" = image-archive ] && [ "$3" = --name ] && [ -f "$archive" ]; then
  exit 0
fi
echo "unexpected kind invocation: $*" >&2
exit 1
"#,
                log_path.display()
            ),
        )
        .expect("kind stub should write");
        for path in [&docker, &kind] {
            let mut permissions = fs::metadata(path)
                .expect("stub metadata should read")
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(path, permissions).expect("stub should chmod");
        }

        load_kind_image_with_binaries(&kind, &docker, "test-cluster", "test:image")
            .expect("archive fallback should run once after direct load retries are exhausted");

        let log = fs::read_to_string(&log_path).expect("commands log should read");
        let direct_count = log
            .lines()
            .filter(|line| line == &"kind load docker-image --name test-cluster test:image")
            .count();
        let archive_count = log
            .lines()
            .filter(|line| line.starts_with("kind load image-archive --name test-cluster "))
            .count();
        let save_count = log
            .lines()
            .filter(|line| {
                line.contains("docker image save --output ") && line.ends_with(" test:image")
            })
            .count();
        assert_eq!(
            direct_count, 3,
            "kind load docker-image should retry exactly three times before falling back:
{log}"
        );
        assert_eq!(
            archive_count, 1,
            "kind image-archive fallback should run once after retries are exhausted:
{log}"
        );
        assert_eq!(
            save_count, 1,
            "docker image save should run once for the single archive fallback:
{log}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn ensure_local_image_pulls_expected_platform_when_missing() {
        let temp = tempfile::tempdir().expect("tempdir should create");
        let docker = temp.path().join("docker");
        let log_path = temp.path().join("commands.log");
        let state_path = temp.path().join("inspect-state");

        fs::write(
            &docker,
            format!(
                "#!/bin/sh\nset -eu\nlog_path='{}'\nstate_path='{}'\nprintf 'docker %s\\n' \"$*\" \
                 >> \"$log_path\"\nif [ \"$1\" = image ] && [ \"$2\" = inspect ] && [ \"$3\" = -f \
                 ] && [ \"$4\" = '{{{{.Id}}}}|{{{{.Architecture}}}}' ] && [ \"$5\" = \
                 'python:3.13-alpine' ]; then\n  if [ ! -f \"$state_path\" ]; then\n    exit 1\n  \
                 fi\n  printf 'sha256:test|arm64\\n'\n  exit 0\nfi\nif [ \"$1\" = pull ] && [ \
                 \"$2\" = --platform ] && [ \"$3\" = 'linux/arm64' ] && [ \"$4\" = \
                 'python:3.13-alpine' ]; then\n  printf pulled > \"$state_path\"\n  exit \
                 0\nfi\necho \"unexpected docker invocation: $*\" >&2\nexit 1\n",
                log_path.display(),
                state_path.display(),
            ),
        )
        .expect("docker stub should write");
        let mut permissions = fs::metadata(&docker)
            .expect("stub metadata should read")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&docker, permissions).expect("stub should chmod");

        let meta = ensure_local_image_with_binaries(&docker, "python:3.13-alpine", "arm64")
            .expect("missing image should be pulled for the expected platform");
        assert_eq!(
            meta,
            DockerImageMeta {
                id: "sha256:test".to_string(),
                arch: "arm64".to_string(),
            }
        );

        let log = fs::read_to_string(&log_path).expect("commands log should read");
        assert!(
            log.lines()
                .any(|line| line == "docker pull --platform linux/arm64 python:3.13-alpine"),
            "docker pull should request the expected platform:\n{log}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn ensure_local_image_repulls_expected_platform_when_local_arch_is_wrong() {
        let temp = tempfile::tempdir().expect("tempdir should create");
        let docker = temp.path().join("docker");
        let log_path = temp.path().join("commands.log");
        let state_path = temp.path().join("inspect-state");

        fs::write(
            &docker,
            format!(
                r#"#!/bin/sh
set -eu
log_path='{}'
state_path='{}'
printf 'docker %s
' "$*" >> "$log_path"
if [ "$1" = image ] && [ "$2" = inspect ] && [ "$3" = -f ] && [ "$4" = '{{{{.Id}}}}|{{{{.Architecture}}}}' ] && [ "$5" = 'python:3.13-alpine' ]; then
  if [ -f "$state_path" ]; then
    printf 'sha256:test|arm64
'
  else
    printf 'sha256:stale|amd64
'
  fi
  exit 0
fi
if [ "$1" = pull ] && [ "$2" = --platform ] && [ "$3" = 'linux/arm64' ] && [ "$4" = 'python:3.13-alpine' ]; then
  printf pulled > "$state_path"
  exit 0
fi
echo "unexpected docker invocation: $*" >&2
exit 1
"#,
                log_path.display(),
                state_path.display(),
            ),
        )
        .expect("docker stub should write");
        let mut permissions = fs::metadata(&docker)
            .expect("stub metadata should read")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&docker, permissions).expect("stub should chmod");

        let meta = ensure_local_image_with_binaries(&docker, "python:3.13-alpine", "arm64")
            .expect("wrong-arch image should be repulled for the expected platform");
        assert_eq!(
            meta,
            DockerImageMeta {
                id: "sha256:test".to_string(),
                arch: "arm64".to_string(),
            }
        );

        let log = fs::read_to_string(&log_path).expect("commands log should read");
        assert!(
            log.lines()
                .any(|line| line == "docker pull --platform linux/arm64 python:3.13-alpine"),
            "wrong-arch local images should be repulled for the expected platform:
{log}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_app_image_builds_a_local_wrapper_image() {
        let temp = tempfile::tempdir().expect("tempdir should create");
        let docker = temp.path().join("docker");
        let log_path = temp.path().join("commands.log");
        let state_path = temp.path().join("inspect-state");
        let dockerfile_copy = temp.path().join("Dockerfile");

        fs::write(
            &docker,
            format!(
                r#"#!/bin/sh
set -eu
log_path='{}'
state_path='{}'
dockerfile_copy='{}'
printf 'docker %s
' "$*" >> "$log_path"
if [ "$1" = image ] && [ "$2" = inspect ] && [ "$3" = -f ] && [ "$4" = '{{{{.Id}}}}|{{{{.Architecture}}}}' ] && [ "$5" = 'python:3.13-alpine' ]; then
  if [ ! -f "$state_path" ]; then
    exit 1
  fi
  printf 'sha256:test|arm64
'
  exit 0
fi
if [ "$1" = pull ] && [ "$2" = --platform ] && [ "$3" = 'linux/arm64' ] && [ "$4" = 'python:3.13-alpine' ]; then
  printf pulled > "$state_path"
  exit 0
fi
if [ "$1" = build ] && [ "$2" = --platform ] && [ "$3" = 'linux/arm64' ] && [ "$4" = -t ] && [ "$5" = 'amber-mixed-run-test-app:arm64' ]; then
  cp "$6/Dockerfile" "$dockerfile_copy"
  exit 0
fi
echo "unexpected docker invocation: $*" >&2
exit 1
"#,
                log_path.display(),
                state_path.display(),
                dockerfile_copy.display(),
            ),
        )
        .expect("docker stub should write");
        let mut permissions = fs::metadata(&docker)
            .expect("stub metadata should read")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&docker, permissions).expect("stub should chmod");

        let local_tag = build_test_app_image_with_binaries(&docker, "python:3.13-alpine", "arm64")
            .expect("test app image should build a local wrapper image");
        assert_eq!(local_tag, "amber-mixed-run-test-app:arm64");

        let log = fs::read_to_string(&log_path).expect("commands log should read");
        assert!(
            log.lines().any(|line| {
                line == "docker build --platform linux/arm64 -t amber-mixed-run-test-app:arm64"
                    || line.starts_with(
                        "docker build --platform linux/arm64 -t amber-mixed-run-test-app:arm64 ",
                    )
            }),
            "test app image should be built as a local wrapper image:
{log}"
        );
        assert_eq!(
            fs::read_to_string(&dockerfile_copy).expect("copied Dockerfile should read"),
            "FROM python:3.13-alpine
",
            "test app image wrapper should inherit from the upstream python base image",
        );
    }
}
