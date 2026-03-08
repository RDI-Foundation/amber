use std::{
    env, fs,
    net::{SocketAddr, TcpListener},
    path::Path,
    process::{Command, Stdio},
};

use serde_json::Value;

fn pick_free_port() -> u16 {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    listener.local_addr().unwrap().port()
}

fn workspace_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root")
        .to_path_buf()
}

#[test]
fn run_rejects_unsupported_direct_plan_version() {
    let workspace_root = workspace_root();
    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs root");
    let temp = tempfile::Builder::new()
        .prefix("direct-plan-version-")
        .tempdir_in(&outputs_root)
        .expect("failed to create temp output directory");
    let direct_out = temp.path().join("out");
    let port = pick_free_port();
    let manifest_path = temp.path().join("scenario.json5");
    fs::write(
        &manifest_path,
        format!(
            r#"{{
  manifest_version: "0.1.0",
  program: {{
    path: "/usr/bin/env",
    args: ["python3", "-m", "http.server", "{port}", "--bind", "127.0.0.1"],
    network: {{
      endpoints: [
        {{ name: "http", port: {port}, protocol: "http" }},
      ],
    }},
  }},
  provides: {{
    http: {{ kind: "http", endpoint: "http" }},
  }},
  exports: {{
    http: "http",
  }},
}}
"#
        ),
    )
    .expect("failed to write manifest");

    let compile = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--direct")
        .arg(&direct_out)
        .arg(&manifest_path)
        .output()
        .expect("failed to run amber compile --direct");
    assert!(
        compile.status.success(),
        "amber compile --direct failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&compile.stdout),
        String::from_utf8_lossy(&compile.stderr)
    );

    let plan_path = direct_out.join("direct-plan.json");
    let mut plan: Value = serde_json::from_str(
        &fs::read_to_string(&plan_path).expect("failed to read direct-plan.json"),
    )
    .expect("direct-plan.json should be valid JSON");
    plan["version"] = Value::String("999".to_string());
    fs::write(
        &plan_path,
        serde_json::to_vec_pretty(&plan).expect("plan should serialize"),
    )
    .expect("failed to rewrite direct-plan.json");

    let run = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("run")
        .arg(&direct_out)
        .output()
        .expect("failed to run amber run");
    assert!(!run.status.success(), "amber run unexpectedly succeeded");
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(
        stderr.contains("unsupported direct plan version"),
        "expected version error in stderr, got:\n{stderr}"
    );
}

#[cfg(target_os = "linux")]
mod linux_direct_smoke {
    use std::{
        io::{Read, Write},
        net::TcpStream,
        thread,
        time::{Duration, Instant},
    };

    use super::*;

    fn wait_for_http(port: u16, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Ok(mut stream) = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port))) {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
                let _ = stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
                let mut buf = [0u8; 1024];
                let Ok(n) = stream.read(&mut buf) else {
                    thread::sleep(Duration::from_millis(150));
                    continue;
                };
                let response = String::from_utf8_lossy(&buf[..n]);
                if response.contains("HTTP/1.0 200") || response.contains("HTTP/1.1 200") {
                    return true;
                }
            }
            thread::sleep(Duration::from_millis(150));
        }
        false
    }

    fn fetch_http_body(port: u16, path: &str) -> Option<String> {
        let mut stream = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port))).ok()?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let request =
            format!("GET /{path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).ok()?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).ok()?;
        let response = String::from_utf8_lossy(&buf);
        let (_, body) = response.split_once("\r\n\r\n")?;
        Some(body.trim().to_string())
    }

    fn wait_for_body(port: u16, path: &str, expected: &str, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if fetch_http_body(port, path).as_deref() == Some(expected) {
                return;
            }
            thread::sleep(Duration::from_millis(150));
        }
        panic!("did not observe {path}={expected} on 127.0.0.1:{port}");
    }

    fn wait_for_exit(
        child: &mut std::process::Child,
        timeout: Duration,
    ) -> Option<std::process::ExitStatus> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Ok(Some(status)) = child.try_wait() {
                return Some(status);
            }
            thread::sleep(Duration::from_millis(100));
        }
        None
    }

    fn cargo_target_dir(workspace_root: &Path) -> std::path::PathBuf {
        match env::var_os("CARGO_TARGET_DIR") {
            Some(dir) => {
                let dir = std::path::PathBuf::from(dir);
                if dir.is_absolute() {
                    dir
                } else {
                    workspace_root.join(dir)
                }
            }
            None => workspace_root.join("target"),
        }
    }

    fn ensure_runtime_binaries_built(workspace_root: &Path) -> std::path::PathBuf {
        let build_runtime = Command::new("cargo")
            .current_dir(workspace_root)
            .arg("build")
            .arg("-q")
            .arg("-p")
            .arg("amber-router")
            .arg("-p")
            .arg("amber-helper")
            .output()
            .expect("failed to build runtime binaries for direct smoke test");
        if !build_runtime.status.success() {
            panic!(
                "failed to build runtime binaries\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
                build_runtime.status,
                String::from_utf8_lossy(&build_runtime.stdout),
                String::from_utf8_lossy(&build_runtime.stderr)
            );
        }
        cargo_target_dir(workspace_root).join("debug")
    }

    fn spawn_amber_run(
        direct_out: &Path,
        runtime_bin_dir: &Path,
        extra_env: &[(&str, &str)],
    ) -> std::process::Child {
        spawn_amber_run_with_args(direct_out, runtime_bin_dir, &[], extra_env)
    }

    fn spawn_amber_run_with_args(
        direct_out: &Path,
        runtime_bin_dir: &Path,
        extra_args: &[&str],
        extra_env: &[(&str, &str)],
    ) -> std::process::Child {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_amber"));
        cmd.arg("run")
            .arg(direct_out)
            .args(extra_args)
            .env("AMBER_RUNTIME_BIN_DIR", runtime_bin_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in extra_env {
            cmd.env(key, value);
        }
        cmd.spawn().expect("failed to start amber run")
    }

    fn spawn_amber_proxy(
        direct_out: &Path,
        export_name: &str,
        export_port: u16,
    ) -> std::process::Child {
        Command::new(env!("CARGO_BIN_EXE_amber"))
            .arg("proxy")
            .arg(direct_out)
            .arg("--export")
            .arg(format!("{export_name}=127.0.0.1:{export_port}"))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to start amber proxy")
    }

    fn drain_pipes(child: &mut std::process::Child) -> (String, String) {
        let mut stdout = String::new();
        if let Some(mut pipe) = child.stdout.take() {
            let _ = pipe.read_to_string(&mut stdout);
        }

        let mut stderr = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr);
        }

        (stdout, stderr)
    }

    fn kill_child(child: &mut std::process::Child) -> Option<std::process::ExitStatus> {
        let _ = child.kill();
        child.wait().ok()
    }

    fn signal_int(child: &std::process::Child) {
        let Ok(pid) = i32::try_from(child.id()) else {
            return;
        };
        let _ = unsafe { libc::kill(pid, libc::SIGINT) };
    }

    fn assert_http_reachable_or_dump(
        amber_run: &mut std::process::Child,
        proxy: &mut std::process::Child,
        port: u16,
        process_name: &str,
    ) {
        if wait_for_http(port, Duration::from_secs(20)) {
            return;
        }

        let proxy_status = proxy
            .try_wait()
            .ok()
            .flatten()
            .or_else(|| kill_child(proxy));
        let amber_run_status = amber_run
            .try_wait()
            .ok()
            .flatten()
            .or_else(|| kill_child(amber_run));

        let (proxy_stdout, proxy_stderr) = drain_pipes(proxy);
        let (amber_run_stdout, amber_run_stderr) = drain_pipes(amber_run);

        let proxy_status_text = proxy_status
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let amber_run_status_text = amber_run_status
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        panic!(
            "{process_name} did not become reachable on 127.0.0.1:{port}\namber proxy status: \
             {proxy_status_text}\namber proxy stdout:\n{proxy_stdout}\namber proxy \
             stderr:\n{proxy_stderr}\namber run status: {amber_run_status_text}\namber run \
             stdout:\n{amber_run_stdout}\namber run stderr:\n{amber_run_stderr}"
        );
    }

    fn compile_direct_or_panic(direct_out: &Path, manifest_path: &Path) {
        let compile = Command::new(env!("CARGO_BIN_EXE_amber"))
            .arg("compile")
            .arg("--direct")
            .arg(direct_out)
            .arg(manifest_path)
            .output()
            .expect("failed to run amber compile --direct");
        if !compile.status.success() {
            panic!(
                "amber compile --direct failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
                compile.status,
                String::from_utf8_lossy(&compile.stdout),
                String::from_utf8_lossy(&compile.stderr)
            );
        }
    }

    fn shutdown_direct_runtime(
        amber_run: &mut std::process::Child,
        proxy: &mut std::process::Child,
    ) {
        signal_int(proxy);
        signal_int(amber_run);

        let proxy_status = wait_for_exit(proxy, Duration::from_secs(20))
            .expect("amber proxy did not exit after SIGINT");
        assert!(
            proxy_status.success(),
            "amber proxy failed with status {proxy_status}"
        );

        let status = wait_for_exit(amber_run, Duration::from_secs(20))
            .expect("amber run did not exit after SIGINT");
        assert!(status.success(), "amber run failed with status {status}");
    }

    #[test]
    #[ignore = "requires local runtime binaries and spawns direct processes"]
    fn direct_smoke_python_http_server_starts_and_stops() {
        let workspace_root = workspace_root();

        let outputs_root = workspace_root.join("target").join("cli-test-outputs");
        fs::create_dir_all(&outputs_root).expect("failed to create outputs root");
        let temp = tempfile::Builder::new()
            .prefix("direct-smoke-")
            .tempdir_in(&outputs_root)
            .expect("failed to create temp test dir");

        let port = pick_free_port();
        let manifest_path = temp.path().join("scenario.json5");
        fs::write(
            &manifest_path,
            format!(
                r#"{{
  manifest_version: "0.1.0",
  program: {{
    path: "/usr/bin/env",
    args: ["python3", "-m", "http.server", "{port}", "--bind", "127.0.0.1"],
    network: {{
      endpoints: [
        {{ name: "http", port: {port}, protocol: "http" }},
      ],
    }},
  }},
  provides: {{
    http: {{ kind: "http", endpoint: "http" }},
  }},
  exports: {{
    http: "http",
  }},
}}
"#
            ),
        )
        .expect("failed to write manifest");

        let direct_out = temp.path().join("out");
        compile_direct_or_panic(&direct_out, &manifest_path);

        assert!(
            direct_out.join("direct-plan.json").is_file(),
            "missing direct-plan.json in direct output"
        );
        assert!(
            direct_out.join("run.sh").is_file(),
            "missing run.sh in direct output"
        );

        let runtime_bin_dir = ensure_runtime_binaries_built(&workspace_root);
        let mut child = spawn_amber_run(&direct_out, runtime_bin_dir.as_path(), &[]);
        let export_port = pick_free_port();
        let mut proxy = spawn_amber_proxy(&direct_out, "http", export_port);
        assert_http_reachable_or_dump(&mut child, &mut proxy, export_port, "direct server");

        shutdown_direct_runtime(&mut child, &mut proxy);
    }

    #[test]
    #[ignore = "requires local runtime binaries and spawns direct processes"]
    fn direct_smoke_resolves_relative_program_path_from_manifest_dir() {
        let workspace_root = workspace_root();

        let outputs_root = workspace_root.join("target").join("cli-test-outputs");
        fs::create_dir_all(&outputs_root).expect("failed to create outputs root");
        let temp = tempfile::Builder::new()
            .prefix("direct-relative-path-smoke-")
            .tempdir_in(&outputs_root)
            .expect("failed to create temp test dir");

        let port = pick_free_port();
        let bin_dir = temp.path().join("bin");
        fs::create_dir_all(&bin_dir).expect("failed to create bin directory");
        let script = bin_dir.join("serve.sh");
        fs::write(
            &script,
            format!("#!/bin/sh\nexec python3 -m http.server {port} --bind 127.0.0.1\n"),
        )
        .expect("failed to write script");
        use std::os::unix::fs::PermissionsExt as _;
        let mut perms = fs::metadata(&script)
            .expect("script metadata")
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).expect("chmod script");

        let manifest_path = temp.path().join("scenario.json5");
        fs::write(
            &manifest_path,
            format!(
                r#"{{
  manifest_version: "0.1.0",
  program: {{
    path: "./bin/serve.sh",
    network: {{
      endpoints: [
        {{ name: "http", port: {port}, protocol: "http" }},
      ],
    }},
  }},
  provides: {{
    http: {{ kind: "http", endpoint: "http" }},
  }},
  exports: {{
    http: "http",
  }},
}}
"#
            ),
        )
        .expect("failed to write manifest");

        let direct_out = temp.path().join("out");
        compile_direct_or_panic(&direct_out, &manifest_path);

        let runtime_bin_dir = ensure_runtime_binaries_built(&workspace_root);
        let mut child = spawn_amber_run(&direct_out, runtime_bin_dir.as_path(), &[]);
        let export_port = pick_free_port();
        let mut proxy = spawn_amber_proxy(&direct_out, "http", export_port);
        assert_http_reachable_or_dump(
            &mut child,
            &mut proxy,
            export_port,
            "relative-path direct server",
        );

        shutdown_direct_runtime(&mut child, &mut proxy);
    }

    #[test]
    #[ignore = "requires local runtime binaries and spawns direct processes"]
    fn direct_smoke_mount_under_run_with_helper() {
        let workspace_root = workspace_root();

        let outputs_root = workspace_root.join("target").join("cli-test-outputs");
        fs::create_dir_all(&outputs_root).expect("failed to create outputs root");
        let temp = tempfile::Builder::new()
            .prefix("direct-mount-run-smoke-")
            .tempdir_in(&outputs_root)
            .expect("failed to create temp test dir");

        let port = pick_free_port();
        let bin_dir = temp.path().join("bin");
        fs::create_dir_all(&bin_dir).expect("failed to create bin directory");
        let script = bin_dir.join("serve-with-mount.sh");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\nset -eu\ncat /run/app.txt >/dev/null\nexec python3 -m http.server \
                 {port} --bind 127.0.0.1\n"
            ),
        )
        .expect("failed to write script");
        use std::os::unix::fs::PermissionsExt as _;
        let mut perms = fs::metadata(&script)
            .expect("script metadata")
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).expect("chmod script");

        let manifest_path = temp.path().join("scenario.json5");
        fs::write(
            &manifest_path,
            format!(
                r#"{{
  manifest_version: "0.1.0",
  config_schema: {{
    type: "object",
    properties: {{
      app: {{ type: "string" }},
    }},
    required: ["app"],
  }},
  program: {{
    path: "./bin/serve-with-mount.sh",
    mounts: [
      {{ path: "/run/app.txt", from: "config.app" }},
    ],
    network: {{
      endpoints: [
        {{ name: "http", port: {port}, protocol: "http" }},
      ],
    }},
  }},
  provides: {{
    http: {{ kind: "http", endpoint: "http" }},
  }},
  exports: {{
    http: "http",
  }},
}}
"#
            ),
        )
        .expect("failed to write manifest");

        let direct_out = temp.path().join("out");
        compile_direct_or_panic(&direct_out, &manifest_path);

        let runtime_bin_dir = ensure_runtime_binaries_built(&workspace_root);
        let mut child = spawn_amber_run(
            &direct_out,
            runtime_bin_dir.as_path(),
            &[("AMBER_CONFIG_APP", "hello")],
        );
        let export_port = pick_free_port();
        let mut proxy = spawn_amber_proxy(&direct_out, "http", export_port);
        assert_http_reachable_or_dump(&mut child, &mut proxy, export_port, "mount direct server");

        shutdown_direct_runtime(&mut child, &mut proxy);
    }

    #[test]
    #[ignore = "requires local runtime binaries and spawns direct processes"]
    fn direct_smoke_storage_persists_across_upgrade() {
        use std::os::unix::fs::PermissionsExt as _;

        let workspace_root = workspace_root();

        let outputs_root = workspace_root.join("target").join("cli-test-outputs");
        fs::create_dir_all(&outputs_root).expect("failed to create outputs root");
        let temp = tempfile::Builder::new()
            .prefix("direct-storage-upgrade-smoke-")
            .tempdir_in(&outputs_root)
            .expect("failed to create temp test dir");

        let bin_dir = temp.path().join("bin");
        fs::create_dir_all(&bin_dir).expect("failed to create bin directory");
        let script = bin_dir.join("serve-state.sh");
        fs::write(
            &script,
            r#"#!/bin/sh
set -eu
version="$1"
initial_state="$2"
mkdir -p /var/lib/app /tmp/www
if [ ! -f /var/lib/app/state.txt ]; then
  printf '%s\n' "$initial_state" >/var/lib/app/state.txt
fi
printf '%s\n' "$version" >/tmp/www/version.txt
cp /var/lib/app/state.txt /tmp/www/state.txt
exec python3 -m http.server 8080 --bind 127.0.0.1 -d /tmp/www
"#,
        )
        .expect("failed to write storage script");
        let mut perms = fs::metadata(&script)
            .expect("script metadata")
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).expect("chmod script");

        let child_path = temp.path().join("app.json5");
        let root_path = temp.path().join("scenario.json5");
        fs::write(
            &root_path,
            r##"{
  manifest_version: "0.1.0",
  resources: {
    state: { kind: "storage" },
  },
  components: {
    app: "./app.json5",
  },
  bindings: [
    { to: "#app.state", from: "resources.state" },
  ],
  exports: {
    http: "#app.http",
  },
}
"##,
        )
        .expect("failed to write root manifest");

        let write_child = |version: &str, initial_state: &str| {
            fs::write(
                &child_path,
                format!(
                    r#"{{
  manifest_version: "0.1.0",
  slots: {{
    state: {{ kind: "storage" }},
  }},
  program: {{
    path: "./bin/serve-state.sh",
    args: ["{version}", "{initial_state}"],
    mounts: [
      {{ path: "/var/lib/app", from: "slots.state" }},
    ],
    network: {{
      endpoints: [
        {{ name: "http", port: 8080, protocol: "http" }},
      ],
    }},
  }},
  provides: {{
    http: {{ kind: "http", endpoint: "http" }},
  }},
  exports: {{
    http: "http",
  }},
}}
"#
                ),
            )
            .expect("failed to write child manifest");
        };

        let direct_out = temp.path().join("out");
        let storage_root = temp.path().join("persistent-state");
        let runtime_bin_dir = ensure_runtime_binaries_built(&workspace_root);

        write_child("version-v1", "persisted-v1");
        compile_direct_or_panic(&direct_out, &root_path);

        let storage_root_arg = storage_root.to_string_lossy().into_owned();
        let mut amber_run = spawn_amber_run_with_args(
            &direct_out,
            runtime_bin_dir.as_path(),
            &["--storage-root", storage_root_arg.as_str()],
            &[],
        );
        let export_port = pick_free_port();
        let mut proxy = spawn_amber_proxy(&direct_out, "http", export_port);
        assert_http_reachable_or_dump(
            &mut amber_run,
            &mut proxy,
            export_port,
            "direct storage server v1",
        );
        wait_for_body(
            export_port,
            "version.txt",
            "version-v1",
            Duration::from_secs(20),
        );
        wait_for_body(
            export_port,
            "state.txt",
            "persisted-v1",
            Duration::from_secs(20),
        );
        shutdown_direct_runtime(&mut amber_run, &mut proxy);

        write_child("version-v2", "persisted-v2");
        compile_direct_or_panic(&direct_out, &root_path);

        let mut amber_run = spawn_amber_run_with_args(
            &direct_out,
            runtime_bin_dir.as_path(),
            &["--storage-root", storage_root_arg.as_str()],
            &[],
        );
        let export_port = pick_free_port();
        let mut proxy = spawn_amber_proxy(&direct_out, "http", export_port);
        assert_http_reachable_or_dump(
            &mut amber_run,
            &mut proxy,
            export_port,
            "direct storage server v2",
        );
        wait_for_body(
            export_port,
            "version.txt",
            "version-v2",
            Duration::from_secs(20),
        );
        wait_for_body(
            export_port,
            "state.txt",
            "persisted-v1",
            Duration::from_secs(20),
        );
        shutdown_direct_runtime(&mut amber_run, &mut proxy);
    }

    #[test]
    #[ignore = "requires local runtime binaries and spawns direct processes"]
    fn direct_smoke_does_not_leak_host_env_into_component() {
        let workspace_root = workspace_root();

        let outputs_root = workspace_root.join("target").join("cli-test-outputs");
        fs::create_dir_all(&outputs_root).expect("failed to create outputs root");
        let temp = tempfile::Builder::new()
            .prefix("direct-env-scrub-smoke-")
            .tempdir_in(&outputs_root)
            .expect("failed to create temp test dir");

        let port = pick_free_port();
        let bin_dir = temp.path().join("bin");
        fs::create_dir_all(&bin_dir).expect("failed to create bin directory");
        let script = bin_dir.join("check-env.sh");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\nset -eu\nif [ \"${{HOST_SECRET+x}}\" = x ]; then\n  echo \
                 \"HOST_SECRET leaked into component\" >&2\n  exit 42\nfi\nexec python3 -m \
                 http.server {port} --bind 127.0.0.1\n"
            ),
        )
        .expect("failed to write script");
        use std::os::unix::fs::PermissionsExt as _;
        let mut perms = fs::metadata(&script)
            .expect("script metadata")
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).expect("chmod script");

        let manifest_path = temp.path().join("scenario.json5");
        fs::write(
            &manifest_path,
            format!(
                r#"{{
  manifest_version: "0.1.0",
  program: {{
    path: "./bin/check-env.sh",
    network: {{
      endpoints: [
        {{ name: "http", port: {port}, protocol: "http" }},
      ],
    }},
  }},
  provides: {{
    http: {{ kind: "http", endpoint: "http" }},
  }},
  exports: {{
    http: "http",
  }},
}}
"#
            ),
        )
        .expect("failed to write manifest");

        let direct_out = temp.path().join("out");
        compile_direct_or_panic(&direct_out, &manifest_path);

        let runtime_bin_dir = ensure_runtime_binaries_built(&workspace_root);
        let mut child = spawn_amber_run(
            &direct_out,
            runtime_bin_dir.as_path(),
            &[("HOST_SECRET", "top-secret")],
        );
        let export_port = pick_free_port();
        let mut proxy = spawn_amber_proxy(&direct_out, "http", export_port);
        assert_http_reachable_or_dump(
            &mut child,
            &mut proxy,
            export_port,
            "env-scrub direct server",
        );

        shutdown_direct_runtime(&mut child, &mut proxy);
    }

    #[test]
    #[ignore = "requires local runtime binaries and spawns direct processes"]
    fn direct_smoke_blocks_host_file_reads_outside_allowed_mounts() {
        let workspace_root = workspace_root();

        let outputs_root = workspace_root.join("target").join("cli-test-outputs");
        fs::create_dir_all(&outputs_root).expect("failed to create outputs root");
        let temp = tempfile::Builder::new()
            .prefix("direct-host-fs-smoke-")
            .tempdir_in(&outputs_root)
            .expect("failed to create temp test dir");
        let secret_dir = tempfile::Builder::new()
            .prefix("direct-host-secret-")
            .tempdir_in(&outputs_root)
            .expect("failed to create host secret dir");
        let secret_path = secret_dir.path().join("secret.txt");
        fs::write(&secret_path, "top-secret").expect("failed to write secret file");

        let port = pick_free_port();
        let bin_dir = temp.path().join("bin");
        fs::create_dir_all(&bin_dir).expect("failed to create bin directory");
        let script = bin_dir.join("check-host-fs.sh");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\nset -eu\nif cat '{}' >/dev/null 2>&1; then\n  echo \"host file was \
                 readable inside sandbox\" >&2\n  exit 42\nfi\nexec python3 -m http.server {port} \
                 --bind 127.0.0.1\n",
                secret_path.display()
            ),
        )
        .expect("failed to write script");
        use std::os::unix::fs::PermissionsExt as _;
        let mut perms = fs::metadata(&script)
            .expect("script metadata")
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).expect("chmod script");

        let manifest_path = temp.path().join("scenario.json5");
        fs::write(
            &manifest_path,
            format!(
                r#"{{
  manifest_version: "0.1.0",
  program: {{
    path: "./bin/check-host-fs.sh",
    network: {{
      endpoints: [
        {{ name: "http", port: {port}, protocol: "http" }},
      ],
    }},
  }},
  provides: {{
    http: {{ kind: "http", endpoint: "http" }},
  }},
  exports: {{
    http: "http",
  }},
}}
"#
            ),
        )
        .expect("failed to write manifest");

        let direct_out = temp.path().join("out");
        compile_direct_or_panic(&direct_out, &manifest_path);

        let runtime_bin_dir = ensure_runtime_binaries_built(&workspace_root);
        let mut child = spawn_amber_run(&direct_out, runtime_bin_dir.as_path(), &[]);
        let export_port = pick_free_port();
        let mut proxy = spawn_amber_proxy(&direct_out, "http", export_port);
        assert_http_reachable_or_dump(&mut child, &mut proxy, export_port, "host-fs direct server");

        shutdown_direct_runtime(&mut child, &mut proxy);
    }
}

#[test]
#[ignore = "requires Docker Desktop and runs the Linux direct smoke test inside a container"]
#[cfg(target_os = "macos")]
fn direct_smoke_macos_via_docker_desktop_linux_vm() {
    let workspace_root = workspace_root();
    let mut archive = Command::new("tar");
    archive
        .current_dir(&workspace_root)
        .env("COPYFILE_DISABLE", "1")
        .env("COPY_EXTENDED_ATTRIBUTES_DISABLE", "1")
        .arg("--exclude=.git")
        .arg("--exclude=target")
        .arg("--exclude=manifest/target")
        .arg("--exclude=node/target")
        .arg("-cf")
        .arg("-")
        .arg(".")
        .stdout(Stdio::piped());
    let mut archive = archive
        .spawn()
        .expect("failed to create workspace archive for macOS direct smoke test");

    let mut docker = Command::new("docker");
    docker
        .arg("run")
        .arg("--rm")
        .arg("--privileged")
        .arg("-i")
        .arg("rust:1.93.1-slim-trixie")
        .arg("bash")
        .arg("-c")
        .arg(
            "set -euo pipefail\nexport PATH=/usr/local/cargo/bin:$PATH\nexport \
             DEBIAN_FRONTEND=noninteractive\nmkdir -p /work\ntar -xf - -C /work\ncd \
             /work\napt-get update >/tmp/apt-update.log\napt-get install -y \
             --no-install-recommends bubblewrap ca-certificates g++ libssl-dev pkg-config python3 \
             slirp4netns >/tmp/apt-install.log\nrustup toolchain install nightly-2025-10-30 \
             --profile minimal >/tmp/rustup-install.log\nrustup default nightly-2025-10-30 \
             >/tmp/rustup-default.log\nrustup component add rustfmt clippy \
             >/tmp/rustup-components.log\ncargo test -p amber-cli --all-features \
             direct_smoke_python_http_server_starts_and_stops -- --ignored --nocapture\ncargo \
             test -p amber-cli --all-features direct_smoke_storage_persists_across_upgrade -- \
             --ignored --nocapture",
        )
        .stdin(Stdio::from(
            archive
                .stdout
                .take()
                .expect("workspace archive stdout should be available"),
        ))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = docker
        .output()
        .expect("failed to run docker desktop direct smoke test");
    let archive_status = archive
        .wait()
        .expect("failed to finish workspace archive stream");

    assert!(
        archive_status.success(),
        "workspace archive creation failed with status {archive_status}"
    );

    assert!(
        output.status.success(),
        "docker desktop direct smoke test failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
