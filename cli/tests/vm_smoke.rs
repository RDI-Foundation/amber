#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::{
    env, fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct SpawnedChild {
    child: std::process::Child,
    log_path: PathBuf,
}

fn pick_free_port() -> u16 {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    listener.local_addr().unwrap().port()
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root")
        .to_path_buf()
}

fn cargo_target_dir(workspace_root: &Path) -> PathBuf {
    match env::var_os("CARGO_TARGET_DIR") {
        Some(dir) => {
            let dir = PathBuf::from(dir);
            if dir.is_absolute() {
                dir
            } else {
                workspace_root.join(dir)
            }
        }
        None => workspace_root.join("target"),
    }
}

fn ensure_runtime_binaries_built(workspace_root: &Path) -> PathBuf {
    let build_runtime = Command::new("cargo")
        .current_dir(workspace_root)
        .arg("build")
        .arg("-q")
        .arg("-p")
        .arg("amber-cli")
        .arg("-p")
        .arg("amber-router")
        .output()
        .expect("failed to build runtime binaries for vm smoke test");
    if !build_runtime.status.success() {
        panic!(
            "failed to build vm runtime binaries\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
            build_runtime.status,
            String::from_utf8_lossy(&build_runtime.stdout),
            String::from_utf8_lossy(&build_runtime.stderr)
        );
    }
    cargo_target_dir(workspace_root).join("debug")
}

fn vm_base_image(workspace_root: &Path) -> PathBuf {
    env::var_os("AMBER_VM_SMOKE_BASE_IMAGE")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root.join(default_vm_smoke_base_image_filename()))
}

fn default_vm_smoke_base_image_filename() -> &'static str {
    match env::consts::ARCH {
        "aarch64" => "ubuntu-24.04-minimal-cloudimg-arm64.img",
        "x86_64" => "ubuntu-24.04-minimal-cloudimg-amd64.img",
        other => panic!("vm smoke test supports only aarch64 and x86_64 hosts, found {other}"),
    }
}

fn smoke_timeout() -> Duration {
    env::var("AMBER_VM_SMOKE_TIMEOUT_SECS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_else(|| {
            if env::var_os("AMBER_VM_FORCE_TCG").is_some() {
                Duration::from_secs(2_700)
            } else {
                Duration::from_secs(420)
            }
        })
}

fn compile_vm_or_panic(amber: &Path, output_dir: &Path, manifest_path: &Path, base_image: &Path) {
    let compile = Command::new(amber)
        .arg("compile")
        .arg("--vm")
        .arg(output_dir)
        .arg(manifest_path)
        .env("AMBER_CONFIG_BASE_IMAGE", base_image)
        .output()
        .expect("failed to run amber compile --vm");
    if !compile.status.success() {
        panic!(
            "amber compile --vm failed\nmanifest: {}\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
            manifest_path.display(),
            compile.status,
            String::from_utf8_lossy(&compile.stdout),
            String::from_utf8_lossy(&compile.stderr),
        );
    }
}

fn spawn_amber_run(
    amber: &Path,
    vm_out: &Path,
    runtime_bin_dir: &Path,
    storage_root: &Path,
    base_image: &Path,
    log_path: &Path,
) -> SpawnedChild {
    let stdout = fs::File::create(log_path).expect("failed to create amber run log");
    let stderr = stdout
        .try_clone()
        .expect("failed to clone amber run log handle");
    let mut cmd = Command::new(amber);
    cmd.arg("run")
        .arg("--storage-root")
        .arg(storage_root)
        .arg(vm_out)
        .env("AMBER_RUNTIME_BIN_DIR", runtime_bin_dir)
        .env("AMBER_CONFIG_BASE_IMAGE", base_image)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    if let Some(firmware) = env::var_os("AMBER_VM_AARCH64_FIRMWARE") {
        cmd.env("AMBER_VM_AARCH64_FIRMWARE", firmware);
    }
    if env::var_os("AMBER_VM_FORCE_TCG").is_some() {
        cmd.env("AMBER_VM_FORCE_TCG", "1");
    }
    SpawnedChild {
        child: cmd.spawn().expect("failed to start amber run"),
        log_path: log_path.to_path_buf(),
    }
}

fn spawn_amber_proxy(
    amber: &Path,
    vm_out: &Path,
    api_port: u16,
    bound_port: u16,
    unbound_port: u16,
) -> SpawnedChild {
    let log_path = vm_out.join(".amber-vm-smoke-proxy.log");
    let stdout = fs::File::create(&log_path).expect("failed to create amber proxy log");
    let stderr = stdout
        .try_clone()
        .expect("failed to clone amber proxy log handle");
    let child = Command::new(amber)
        .arg("proxy")
        .arg(vm_out)
        .arg("--export")
        .arg(format!("api=127.0.0.1:{api_port}"))
        .arg("--export")
        .arg(format!("bound=127.0.0.1:{bound_port}"))
        .arg("--export")
        .arg(format!("unbound=127.0.0.1:{unbound_port}"))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("failed to start amber proxy");
    SpawnedChild { child, log_path }
}

fn wait_for_exit(child: &mut SpawnedChild, timeout: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(Some(status)) = child.child.try_wait() {
            return Some(status);
        }
        thread::sleep(Duration::from_millis(100));
    }
    None
}

fn kill_child(child: &mut SpawnedChild) -> Option<std::process::ExitStatus> {
    let _ = child.child.kill();
    child.child.wait().ok()
}

fn signal_int(child: &SpawnedChild) {
    let Ok(pid) = i32::try_from(child.child.id()) else {
        return;
    };
    let _ = unsafe { libc::kill(pid, libc::SIGINT) };
}

fn read_log(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| format!("failed to read {}: {err}", path.display()))
}

fn http_request(port: u16, method: &str, path: &str, body: Option<&str>) -> Option<(u16, String)> {
    let mut stream = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port))).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let body = body.unwrap_or("");
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: \
         {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).ok()?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).ok()?;
    let response = String::from_utf8_lossy(&buf);
    let (head, body) = response.split_once("\r\n\r\n")?;
    let mut head_lines = head.lines();
    let status_line = head_lines.next()?;
    let status = status_line.split_whitespace().nth(1)?.parse().ok()?;
    Some((status, body.trim().to_string()))
}

fn wait_for_body(
    amber_run: &mut SpawnedChild,
    proxy: &mut SpawnedChild,
    port: u16,
    path: &str,
    timeout: Duration,
    predicate: impl Fn(&str) -> bool,
) -> String {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(Some(status)) = amber_run.child.try_wait() {
            panic_with_process_output(
                amber_run,
                proxy,
                format!("amber run exited before 127.0.0.1:{port}{path} was ready: {status}"),
            );
        }
        if let Ok(Some(status)) = proxy.child.try_wait() {
            panic_with_process_output(
                amber_run,
                proxy,
                format!("amber proxy exited before 127.0.0.1:{port}{path} was ready: {status}"),
            );
        }
        if let Some((200, body)) = http_request(port, "GET", path, None)
            && predicate(&body)
        {
            return body;
        }
        thread::sleep(Duration::from_millis(250));
    }
    panic_with_process_output(
        amber_run,
        proxy,
        format!("did not observe expected response on 127.0.0.1:{port}{path}"),
    );
}

fn put_body_or_dump(
    amber_run: &mut SpawnedChild,
    proxy: &mut SpawnedChild,
    port: u16,
    path: &str,
    body: &str,
) -> String {
    match http_request(port, "PUT", path, Some(body)) {
        Some((200, response)) => response,
        other => panic_with_process_output(
            amber_run,
            proxy,
            format!("PUT {path} on 127.0.0.1:{port} failed: {other:?}"),
        ),
    }
}

fn panic_with_process_output(
    amber_run: &mut SpawnedChild,
    proxy: &mut SpawnedChild,
    message: String,
) -> ! {
    let proxy_status = proxy
        .child
        .try_wait()
        .ok()
        .flatten()
        .or_else(|| kill_child(proxy));
    let amber_run_status = amber_run
        .child
        .try_wait()
        .ok()
        .flatten()
        .or_else(|| kill_child(amber_run));
    panic!(
        "{message}\namber proxy status: {}\namber proxy log ({}):\n{}\namber run status: \
         {}\namber run log ({}):\n{}",
        proxy_status
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        proxy.log_path.display(),
        read_log(&proxy.log_path),
        amber_run_status
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        amber_run.log_path.display(),
        read_log(&amber_run.log_path),
    );
}

fn shutdown_vm_runtime(amber_run: &mut SpawnedChild, proxy: &mut SpawnedChild) {
    signal_int(proxy);
    let proxy_status = wait_for_exit(proxy, Duration::from_secs(20)).unwrap_or_else(|| {
        panic_with_process_output(
            amber_run,
            proxy,
            "amber proxy did not exit after SIGINT".to_string(),
        )
    });
    assert!(
        proxy_status.success(),
        "amber proxy failed with status {proxy_status}"
    );

    signal_int(amber_run);
    let run_status = wait_for_exit(amber_run, Duration::from_secs(20)).unwrap_or_else(|| {
        panic_with_process_output(
            amber_run,
            proxy,
            "amber run did not exit after SIGINT".to_string(),
        )
    });
    assert!(
        run_status.success(),
        "amber run failed with status {run_status}"
    );
}

struct VmRunExpectation<'a> {
    run_name: &'a str,
    expected_version: &'a str,
    expected_storage: &'a str,
    expected_ephemeral: &'a str,
}

fn assert_vm_run(
    amber: &Path,
    vm_out: &Path,
    storage_root: &Path,
    logs_dir: &Path,
    runtime_bin_dir: &Path,
    base_image: &Path,
    expectation: VmRunExpectation<'_>,
) {
    let api_port = pick_free_port();
    let bound_port = pick_free_port();
    let unbound_port = pick_free_port();

    let mut amber_run = spawn_amber_run(
        amber,
        vm_out,
        runtime_bin_dir,
        storage_root,
        base_image,
        &logs_dir.join(format!("{}.amber-run.log", expectation.run_name)),
    );
    let mut proxy = spawn_amber_proxy(amber, vm_out, api_port, bound_port, unbound_port);
    let timeout = smoke_timeout();

    let version = wait_for_body(
        &mut amber_run,
        &mut proxy,
        api_port,
        "/version",
        timeout,
        |body| body == expectation.expected_version,
    );
    assert_eq!(version, expectation.expected_version);

    let storage = wait_for_body(
        &mut amber_run,
        &mut proxy,
        api_port,
        "/storage",
        timeout,
        |body| body == expectation.expected_storage,
    );
    assert_eq!(storage, expectation.expected_storage);

    let bound = wait_for_body(
        &mut amber_run,
        &mut proxy,
        bound_port,
        "/reachability",
        timeout,
        |body| body == "reachable:api",
    );
    assert_eq!(bound, "reachable:api");

    let unbound = wait_for_body(
        &mut amber_run,
        &mut proxy,
        unbound_port,
        "/reachability",
        timeout,
        |body| body.starts_with("blocked:"),
    );
    assert!(
        unbound.starts_with("blocked:"),
        "expected unbound reachability failure, got {unbound}"
    );

    let bound_ephemeral = wait_for_body(
        &mut amber_run,
        &mut proxy,
        bound_port,
        "/ephemeral",
        timeout,
        |body| body == "own=owned:bound;api_visible=false",
    );
    assert_eq!(bound_ephemeral, "own=owned:bound;api_visible=false");

    let unbound_ephemeral = wait_for_body(
        &mut amber_run,
        &mut proxy,
        unbound_port,
        "/ephemeral",
        timeout,
        |body| body == "own=owned:unbound;api_visible=false",
    );
    assert_eq!(unbound_ephemeral, "own=owned:unbound;api_visible=false");

    let ephemeral = wait_for_body(
        &mut amber_run,
        &mut proxy,
        api_port,
        "/ephemeral",
        timeout,
        |body| body == expectation.expected_ephemeral,
    );
    assert_eq!(ephemeral, expectation.expected_ephemeral);

    if expectation.expected_version == "v1" && expectation.expected_storage == "seeded by v1" {
        let storage_written = put_body_or_dump(
            &mut amber_run,
            &mut proxy,
            api_port,
            "/storage",
            "remembered across runs",
        );
        assert_eq!(storage_written, "remembered across runs");

        let ephemeral_written = put_body_or_dump(
            &mut amber_run,
            &mut proxy,
            api_port,
            "/ephemeral",
            "discarded after teardown",
        );
        assert_eq!(ephemeral_written, "discarded after teardown");
    }

    shutdown_vm_runtime(&mut amber_run, &mut proxy);
}

#[test]
#[ignore = "requires QEMU and a host-arch Ubuntu cloud image"]
fn vm_smoke_network_storage_and_migration_example() {
    let workspace_root = workspace_root();
    let base_image = vm_base_image(&workspace_root);
    let default_image = default_vm_smoke_base_image_filename();
    assert!(
        base_image.is_file(),
        "missing VM smoke base image {}; set AMBER_VM_SMOKE_BASE_IMAGE or place {} at the \
         workspace root",
        base_image.display(),
        default_image,
    );

    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs root");
    let temp = tempfile::Builder::new()
        .prefix("vm-smoke-")
        .tempdir_in(&outputs_root)
        .expect("failed to create temp output directory");

    let vm_out = temp.path().join("vm");
    let storage_root = temp.path().join("state");
    let logs_dir = temp.path().join("logs");
    fs::create_dir_all(&logs_dir).expect("failed to create vm smoke log directory");
    let runtime_bin_dir = ensure_runtime_binaries_built(&workspace_root);
    let amber = runtime_bin_dir.join("amber");
    let example_dir = workspace_root.join("examples").join("vm-network-storage");

    compile_vm_or_panic(
        &amber,
        &vm_out,
        &example_dir.join("scenario.json5"),
        &base_image,
    );
    assert_vm_run(
        &amber,
        &vm_out,
        &storage_root,
        &logs_dir,
        &runtime_bin_dir,
        &base_image,
        VmRunExpectation {
            run_name: "run-v1-initial",
            expected_version: "v1",
            expected_storage: "seeded by v1",
            expected_ephemeral: "boot:v1",
        },
    );
    assert_vm_run(
        &amber,
        &vm_out,
        &storage_root,
        &logs_dir,
        &runtime_bin_dir,
        &base_image,
        VmRunExpectation {
            run_name: "run-v1-rerun",
            expected_version: "v1",
            expected_storage: "remembered across runs",
            expected_ephemeral: "boot:v1",
        },
    );

    compile_vm_or_panic(
        &amber,
        &vm_out,
        &example_dir.join("v2").join("scenario.json5"),
        &base_image,
    );
    assert_vm_run(
        &amber,
        &vm_out,
        &storage_root,
        &logs_dir,
        &runtime_bin_dir,
        &base_image,
        VmRunExpectation {
            run_name: "run-v2-migration",
            expected_version: "v2",
            expected_storage: "remembered across runs",
            expected_ephemeral: "boot:v2",
        },
    );
}
