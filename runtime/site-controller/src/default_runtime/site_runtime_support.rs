use super::*;

pub(super) fn remove_dir_if_exists(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    fs::remove_dir_all(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to remove {}", path.display()))
}

pub fn prepare_kubernetes_artifact_namespace(
    run_id: &str,
    site_id: &str,
    artifact_dir: &Path,
) -> Result<String> {
    let namespace = kubernetes_namespace_name(run_id, site_id);
    let kustomization = artifact_dir.join("kustomization.yaml");
    let contents = fs::read_to_string(&kustomization)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", kustomization.display()))?;

    let mut saw_namespace = false;
    let mut out = String::new();
    for line in contents.lines() {
        if line.trim_start().starts_with("namespace:") {
            saw_namespace = true;
            out.push_str("namespace: ");
            out.push_str(&namespace);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    if !saw_namespace {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("namespace: ");
        out.push_str(&namespace);
        out.push('\n');
    }
    if out != contents {
        fs::write(&kustomization, out)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to update {}", kustomization.display()))?;
    }

    Ok(namespace)
}

pub(super) fn site_supervisor_plan_for_site_runtime(
    plan: &SiteControllerRuntimePlan,
    artifact_dir: &Path,
    kubernetes_namespace: Option<String>,
) -> SiteSupervisorPlan {
    SiteSupervisorPlan {
        schema: SITE_PLAN_SCHEMA.to_string(),
        version: SITE_PLAN_VERSION,
        run_id: plan.run_id.clone(),
        mesh_scope: plan.mesh_scope.clone(),
        run_root: plan.run_root.clone(),
        coordinator_pid: 0,
        site_id: plan.site_id.clone(),
        kind: plan.kind,
        artifact_dir: artifact_dir.display().to_string(),
        site_state_root: plan.site_state_root.clone(),
        storage_root: plan.storage_root.clone(),
        runtime_root: plan.runtime_root.clone(),
        router_mesh_port: plan.router_mesh_port,
        compose_project: plan.compose_project.clone(),
        kubernetes_namespace,
        context: plan.context.clone(),
        port_forward_mesh_port: None,
        port_forward_control_port: None,
        observability_endpoint: plan.observability_endpoint.clone(),
        site_controller_plan_path: None,
        site_controller_url: None,
        controller_route_ports: Vec::new(),
        launch_env: plan.launch_env.clone(),
    }
}

pub(super) fn prepare_kubernetes_artifact_for_apply(
    plan: &SiteControllerRuntimePlan,
    artifact_dir: &Path,
) -> Result<SiteSupervisorPlan> {
    debug_assert_eq!(plan.kind, SiteKind::Kubernetes);
    let namespace =
        prepare_kubernetes_artifact_namespace(&plan.run_id, &plan.site_id, artifact_dir)?;
    patch_site_artifacts(
        artifact_dir,
        &plan.run_id,
        &plan.site_id,
        plan.kind,
        &plan.launch_env,
        plan.observability_endpoint.as_deref(),
    )?;
    Ok(site_supervisor_plan_for_site_runtime(
        plan,
        artifact_dir,
        Some(namespace),
    ))
}

pub(super) fn kubernetes_namespace_name(run_id: &str, site_id: &str) -> String {
    let raw = format!("amber-{run_id}-{site_id}");
    let mut out = String::with_capacity(raw.len().min(63));
    let mut last_was_dash = false;

    for ch in raw.chars() {
        let next = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_lowercase()
        } else {
            '-'
        };
        if next == '-' {
            if out.is_empty() || last_was_dash {
                continue;
            }
            last_was_dash = true;
        } else {
            last_was_dash = false;
        }
        out.push(next);
        if out.len() == 63 {
            break;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "amber".to_string()
    } else {
        out
    }
}

pub(super) async fn wait_for_compose_services_running(
    compose_project: &str,
    artifact_root: &Path,
    services: &[String],
    timeout: Duration,
) -> Result<()> {
    if services.is_empty() {
        return Ok(());
    }
    let deadline = Instant::now() + timeout;
    loop {
        let output = compose_command(Some(compose_project), artifact_root)
            .arg("ps")
            .arg("--services")
            .arg("--status")
            .arg("running")
            .args(services)
            .output()
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "failed to query compose child services in {}",
                    artifact_root.display()
                )
            })?;
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            let running = stdout
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .collect::<BTreeSet<_>>();
            if services
                .iter()
                .all(|service| running.contains(service.as_str()))
            {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err(miette::miette!(
                "timed out waiting for compose child services {:?} in {}",
                services,
                artifact_root.display()
            ));
        }
        sleep(Duration::from_millis(200)).await;
    }
}

pub fn walk_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in fs::read_dir(&path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to list {}", path.display()))?
        {
            let entry = entry.into_diagnostic()?;
            let entry_path = entry.path();
            if entry_path.is_dir() {
                stack.push(entry_path);
            } else {
                files.push(entry_path);
            }
        }
    }
    Ok(files)
}

pub fn observability_endpoint_for_site(kind: SiteKind, endpoint: &str) -> Result<String> {
    if !matches!(kind, SiteKind::Compose | SiteKind::Kubernetes) {
        return Ok(endpoint.to_string());
    }

    let mut url = Url::parse(endpoint)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid observability endpoint {endpoint}"))?;
    let should_rewrite = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .map(|addr| addr.is_loopback() || addr.is_unspecified())
                .unwrap_or(false)
    });
    if should_rewrite {
        let host = container_host_for_consumer(SiteKind::Direct, kind);
        url.set_host(Some(&host))
            .map_err(|_| miette::miette!("failed to rewrite observability endpoint {endpoint}"))?;
    }
    Ok(url.to_string())
}

pub(crate) fn reserve_loopback_port() -> Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .into_diagnostic()
        .wrap_err("failed to allocate a loopback port")?;
    Ok(listener.local_addr().into_diagnostic()?.port())
}

pub(super) fn site_supervisor_plan_path(site_state_root: &Path) -> PathBuf {
    site_state_root.join("site-supervisor-plan.json")
}

pub(super) fn desired_links_path(site_state_root: &Path) -> PathBuf {
    site_state_root.join("desired-links.json")
}

pub(super) fn empty_desired_link_state() -> DesiredLinkState {
    DesiredLinkState {
        schema: DESIRED_LINKS_SCHEMA.to_string(),
        version: DESIRED_LINKS_VERSION,
        external_slots: BTreeMap::new(),
        export_peers: Vec::new(),
        external_slot_overlays: BTreeMap::new(),
        export_peer_overlays: BTreeMap::new(),
    }
}

pub(super) fn update_desired_overlay_for_consumer(
    site_state_root: &Path,
    overlay_id: &str,
    overlay: DesiredExternalSlotOverlay,
) -> Result<()> {
    let path = desired_links_path(site_state_root);
    let mut state: DesiredLinkState = if path.is_file() {
        read_json(&path, "desired links")?
    } else {
        empty_desired_link_state()
    };
    state
        .external_slot_overlays
        .insert(overlay_id.to_string(), overlay);
    write_json(&path, &state)
}

pub(super) fn update_desired_overlay_for_provider(
    site_state_root: &Path,
    overlay_id: &str,
    overlay: DesiredExportPeerOverlay,
) -> Result<()> {
    let path = desired_links_path(site_state_root);
    let mut state: DesiredLinkState = if path.is_file() {
        read_json(&path, "desired links")?
    } else {
        empty_desired_link_state()
    };
    state
        .export_peer_overlays
        .insert(overlay_id.to_string(), overlay);
    write_json(&path, &state)
}

pub(super) fn clear_desired_overlay_for_consumer(
    site_state_root: &Path,
    overlay_id: &str,
) -> Result<()> {
    let path = desired_links_path(site_state_root);
    let mut state: DesiredLinkState = if path.is_file() {
        read_json(&path, "desired links")?
    } else {
        return Ok(());
    };
    state.external_slot_overlays.remove(overlay_id);
    write_json(&path, &state)
}

pub(super) fn clear_desired_overlay_for_provider(
    site_state_root: &Path,
    overlay_id: &str,
) -> Result<()> {
    let path = desired_links_path(site_state_root);
    let mut state: DesiredLinkState = if path.is_file() {
        read_json(&path, "desired links")?
    } else {
        return Ok(());
    };
    state.export_peer_overlays.remove(overlay_id);
    write_json(&path, &state)
}

pub(super) fn patch_site_artifacts(
    artifact_dir: &Path,
    run_id: &str,
    site_id: &str,
    kind: SiteKind,
    launch_env: &BTreeMap<String, String>,
    observability_endpoint: Option<&str>,
) -> Result<()> {
    if matches!(kind, SiteKind::Compose) {
        assign_compose_egress_network_subnets(artifact_dir, run_id, site_id)?;
    }
    if matches!(kind, SiteKind::Kubernetes) {
        for env_file_name in [
            DEFAULT_EXTERNAL_ENV_FILE,
            "component-sidecar.env",
            "root-config.env",
            "root-config-secret.env",
        ] {
            let env_file = artifact_dir.join(env_file_name);
            if env_file.is_file() {
                patch_generated_env_file(&env_file, launch_env)?;
            }
        }

        if let Some(endpoint) = observability_endpoint {
            let upstream = observability_endpoint_for_site(kind, endpoint)?;
            for path in walk_files(artifact_dir)? {
                if path.extension().and_then(|ext| ext.to_str()) != Some("yaml") {
                    continue;
                }
                let raw = fs::read_to_string(&path)
                    .into_diagnostic()
                    .wrap_err_with(|| format!("failed to read {}", path.display()))?;
                if !raw.contains(DEFAULT_K8S_OTEL_UPSTREAM) {
                    continue;
                }
                fs::write(&path, raw.replace(DEFAULT_K8S_OTEL_UPSTREAM, &upstream))
                    .into_diagnostic()
                    .wrap_err_with(|| format!("failed to patch {}", path.display()))?;
            }
        }
    }
    Ok(())
}

pub(super) fn patch_generated_env_file(
    path: &Path,
    launch_env: &BTreeMap<String, String>,
) -> Result<()> {
    let raw = fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", path.display()))?;
    let mut out = String::new();
    for line in raw.lines() {
        if let Some((key, _)) = line.split_once('=')
            && let Some(value) = launch_env.get(key.trim())
        {
            out.push_str(key.trim());
            out.push('=');
            out.push_str(value);
            out.push('\n');
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    fs::write(path, out)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", path.display()))
}

pub(super) fn compose_command(project_name: Option<&str>, artifact_dir: &Path) -> Command {
    let mut cmd = Command::new("docker");
    cmd.arg("compose")
        .arg("-f")
        .arg(artifact_dir.join("compose.yaml"));
    if let Some(project_name) = project_name {
        cmd.arg("-p").arg(project_name);
    }
    cmd.current_dir(artifact_dir);
    cmd
}

pub(super) fn kubectl_command(context: Option<&str>) -> Command {
    let mut cmd = Command::new("kubectl");
    if let Some(context) = context {
        cmd.arg("--context").arg(context);
    }
    cmd
}

pub(super) fn ensure_kubernetes_namespace(plan: &SiteSupervisorPlan) -> Result<()> {
    let namespace = required_str(plan.kubernetes_namespace.as_deref(), "kubernetes namespace")?;
    let deadline = Instant::now() + Duration::from_secs(60);
    let context = plan.context.as_deref();
    let mut last_error = None::<String>;
    loop {
        let output = kubectl_command(context)
            .arg("get")
            .arg("namespace")
            .arg(namespace)
            .arg("-o")
            .arg("json")
            .output()
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to query kubernetes namespace `{namespace}`"))?;
        if output.status.success() {
            let namespace_json: serde_json::Value = serde_json::from_slice(&output.stdout)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to parse kubernetes namespace `{namespace}`"))?;
            let is_terminating = namespace_json
                .pointer("/metadata/deletionTimestamp")
                .is_some_and(|value| !value.is_null());
            if !is_terminating {
                return Ok(());
            }
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if stderr.contains("(NotFound)") || stderr.contains("not found") {
                let create_output = kubectl_command(context)
                    .arg("create")
                    .arg("namespace")
                    .arg(namespace)
                    .output()
                    .into_diagnostic()
                    .wrap_err_with(|| {
                        format!("failed to create kubernetes namespace `{namespace}`")
                    })?;
                if create_output.status.success() {
                    return Ok(());
                }
                last_error = Some(
                    String::from_utf8_lossy(&create_output.stderr)
                        .trim()
                        .to_string(),
                );
            } else if !stderr.is_empty() {
                last_error = Some(stderr);
            }
        }
        if Instant::now() >= deadline {
            let detail = last_error
                .as_deref()
                .filter(|detail| !detail.is_empty())
                .map(|detail| format!(": {detail}"))
                .unwrap_or_default();
            return Err(miette::miette!(
                "failed to prepare kubernetes namespace `{namespace}` within 60s{detail}"
            ));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

pub(super) fn ensure_kubernetes_workloads_ready(plan: &SiteSupervisorPlan) -> Result<()> {
    let namespace = required_str(plan.kubernetes_namespace.as_deref(), "kubernetes namespace")?;
    let context = plan.context.as_deref();
    let expected = kubernetes_expected_workloads(Path::new(&plan.artifact_dir))?;
    wait_for_named_kubernetes_resources(
        context,
        namespace,
        "job",
        "condition=complete",
        &expected.jobs,
        &format!("wait for kubernetes jobs for site `{}`", plan.site_id),
    )?;
    wait_for_named_kubernetes_resources(
        context,
        namespace,
        "deployment",
        "condition=available",
        &expected.deployments,
        &format!(
            "wait for kubernetes deployments for site `{}`",
            plan.site_id
        ),
    )?;
    Ok(())
}

#[derive(Default)]
pub(super) struct KubernetesArtifactWorkloads {
    pub(super) jobs: Vec<String>,
    pub(super) deployments: Vec<String>,
}

pub(super) fn kubernetes_expected_workloads(
    artifact_dir: &Path,
) -> Result<KubernetesArtifactWorkloads> {
    let mut jobs = BTreeSet::new();
    let mut deployments = BTreeSet::new();
    for path in walk_files(artifact_dir)? {
        if !matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some("yaml" | "yml")
        ) {
            continue;
        }
        let raw = fs::read_to_string(&path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read kubernetes artifact {}", path.display()))?;
        for document in serde_yaml::Deserializer::from_str(&raw) {
            use serde::Deserialize as _;

            let value = serde_yaml::Value::deserialize(document)
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!("failed to parse kubernetes artifact {}", path.display())
                })?;
            let kind = value
                .get("kind")
                .and_then(serde_yaml::Value::as_str)
                .unwrap_or_default();
            let name = value
                .get("metadata")
                .and_then(serde_yaml::Value::as_mapping)
                .and_then(|metadata| metadata.get(serde_yaml::Value::String("name".to_string())))
                .and_then(serde_yaml::Value::as_str)
                .unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            match kind {
                "Job" => {
                    jobs.insert(name.to_string());
                }
                "Deployment" => {
                    deployments.insert(name.to_string());
                }
                _ => {}
            }
        }
    }
    Ok(KubernetesArtifactWorkloads {
        jobs: jobs.into_iter().collect(),
        deployments: deployments.into_iter().collect(),
    })
}

pub(super) fn wait_for_named_kubernetes_resources(
    context: Option<&str>,
    namespace: &str,
    resource_kind: &str,
    condition: &str,
    names: &[String],
    label: &str,
) -> Result<()> {
    for name in names {
        wait_for_named_kubernetes_resource(
            context,
            namespace,
            resource_kind,
            condition,
            name,
            label,
        )?;
    }
    Ok(())
}

pub(super) fn wait_for_named_kubernetes_resource(
    context: Option<&str>,
    namespace: &str,
    resource_kind: &str,
    condition: &str,
    name: &str,
    label: &str,
) -> Result<()> {
    let resource = format!("{resource_kind}/{name}");
    let deadline = Instant::now() + KUBERNETES_WORKLOAD_READY_TIMEOUT;
    loop {
        let get_output = kubectl_command(context)
            .args(["-n", namespace, "get", resource.as_str()])
            .output()
            .into_diagnostic()
            .wrap_err_with(|| format!("{label}: query {resource}"))?;
        if !get_output.status.success() {
            if Instant::now() >= deadline {
                let stderr = String::from_utf8_lossy(&get_output.stderr)
                    .trim()
                    .to_string();
                let detail = if stderr.is_empty() {
                    format!("status {}", get_output.status)
                } else {
                    stderr
                };
                return Err(miette::miette!("{label} failed: {detail}"));
            }
            std::thread::sleep(Duration::from_millis(250));
            continue;
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout = format!("{}s", remaining.as_secs().max(1));
        let wait_output = kubectl_command(context)
            .args([
                "-n",
                namespace,
                "wait",
                "--for",
                condition,
                "--timeout",
                timeout.as_str(),
                resource.as_str(),
            ])
            .output()
            .into_diagnostic()
            .wrap_err_with(|| format!("{label}: wait for {resource}"))?;
        if wait_output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&wait_output.stderr)
            .trim()
            .to_string();
        if stderr.contains("not found") && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(250));
            continue;
        }
        let detail = if stderr.is_empty() {
            format!("status {}", wait_output.status)
        } else {
            stderr
        };
        return Err(miette::miette!("{label} failed: {detail}"));
    }
}

pub(super) fn mesh_protocol(protocol: NetworkProtocol) -> Result<MeshProtocol> {
    Ok(match protocol {
        NetworkProtocol::Http | NetworkProtocol::Https => MeshProtocol::Http,
        NetworkProtocol::Tcp => MeshProtocol::Tcp,
        _ => {
            return Err(miette::miette!(
                "mixed-site mesh links do not support protocol `{protocol}`"
            ));
        }
    })
}

pub(crate) fn site_ready_timeout_for_kind(kind: SiteKind) -> Duration {
    match kind {
        SiteKind::Kubernetes => KUBERNETES_WORKLOAD_READY_TIMEOUT + KUBERNETES_SITE_READY_BUFFER,
        SiteKind::Direct | SiteKind::Compose | SiteKind::Vm => Duration::from_secs(120),
    }
}

pub(super) fn amber_cli_executable() -> Result<PathBuf> {
    if let Some(path) = env::var_os("CARGO_BIN_EXE_amber") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
    }

    let current = env::current_exe()
        .into_diagnostic()
        .wrap_err("failed to resolve amber executable path")?;
    let exe_name = format!("amber{}", std::env::consts::EXE_SUFFIX);
    for dir in [current.parent(), current.parent().and_then(Path::parent)]
        .into_iter()
        .flatten()
    {
        let candidate = dir.join(&exe_name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(miette::miette!(
        "failed to locate the amber executable next to {}",
        current.display()
    ))
}

pub(crate) fn spawn_detached_child(
    work_dir: &Path,
    log_path: &Path,
    build: impl FnOnce(&mut Command),
) -> Result<Child> {
    #[cfg(unix)]
    use std::os::unix::process::CommandExt as _;

    let exe = amber_cli_executable()?;
    let log = fs::File::create(log_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create log {}", log_path.display()))?;
    let log_err = log
        .try_clone()
        .into_diagnostic()
        .wrap_err("failed to clone log handle")?;
    let mut cmd = Command::new(exe);
    cmd.current_dir(work_dir);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::from(log));
    cmd.stderr(Stdio::from(log_err));
    #[cfg(unix)]
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    build(&mut cmd);
    cmd.spawn().into_diagnostic().wrap_err_with(|| {
        format!(
            "failed to spawn background amber process in {}",
            work_dir.display()
        )
    })
}

pub(super) async fn stop_child(child: &mut Child) -> Result<()> {
    #[cfg(unix)]
    {
        terminate_recorded_processes(&[child.id()]).await?;
        let _ = child.wait();
        Ok(())
    }

    #[cfg(not(unix))]
    {
        send_sigterm(child.id());
        let _ = wait_for_child_exit(child, PROCESS_SHUTDOWN_GRACE_PERIOD).await;
        Ok(())
    }
}

#[cfg(not(unix))]
pub(super) async fn wait_for_child_exit(child: &mut Child, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait().into_diagnostic()?.is_some() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }
}

pub(super) async fn wait_for_pid_exit(pid: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if !pid_is_alive(pid) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        sleep(Duration::from_millis(100)).await;
    }
}

pub(super) async fn router_mesh_listener_ready(addr: SocketAddr) -> bool {
    tokio::net::TcpStream::connect(addr).await.is_ok()
}

pub(super) async fn wait_for_socket_listener(addr: SocketAddr) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if router_mesh_listener_ready(addr).await {
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }
    Err(miette::miette!("timed out waiting for listener {}", addr))
}

pub(super) fn endpoint_returns_http_response_blocking(
    addr: SocketAddr,
    timeout: Duration,
) -> Result<bool> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if let Ok(mut stream) =
            std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(100))
        {
            let _ =
                stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
            let mut buf = [0u8; 32];
            if let Ok(read) = stream.read(&mut buf)
                && read > 0
                && buf[..read].starts_with(b"HTTP/")
            {
                return Ok(true);
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(false)
}

pub(super) fn endpoint_accepts_stable_connection_blocking(
    addr: SocketAddr,
    timeout: Duration,
) -> Result<bool> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(false)
}

pub(super) fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

pub(super) fn pid_is_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let alive = if unsafe { libc::kill(pid as i32, 0) } == 0 {
            true
        } else {
            std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
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
fn process_status_code(pid: u32) -> Option<char> {
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
    parse_process_status_code(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(unix)]
fn parse_process_status_code(raw: &str) -> Option<char> {
    raw.split_whitespace()
        .next()?
        .chars()
        .next()
        .map(|state| state.to_ascii_uppercase())
}

#[cfg(unix)]
pub(super) fn send_sigterm(pid: u32) {
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
}

#[cfg(not(unix))]
pub(super) fn send_sigterm(_pid: u32) {}

#[cfg(unix)]
pub(super) fn send_signal_to_pids(pids: &[u32], signal: i32) {
    for pid in pids {
        unsafe {
            libc::kill(*pid as i32, signal);
        }
    }
}

#[cfg(not(unix))]
pub(super) fn send_signal_to_pids(_pids: &[u32], _signal: i32) {}

#[cfg(unix)]
pub(super) fn send_signal_to_process_group(root_pid: u32, signal: i32) {
    unsafe {
        libc::kill(-(root_pid as i32), signal);
    }
}

#[cfg(not(unix))]
pub(super) fn send_signal_to_process_group(_root_pid: u32, _signal: i32) {}

pub(super) fn process_tree_postorder(root_pid: u32) -> Result<Vec<u32>> {
    Ok(vec![root_pid])
}

pub(super) async fn terminate_recorded_processes(root_pids: &[u32]) -> Result<()> {
    for pid in root_pids {
        send_sigterm(*pid);
        if !wait_for_pid_exit(*pid, PROCESS_SHUTDOWN_GRACE_PERIOD).await {
            #[cfg(unix)]
            unsafe {
                libc::kill(*pid as i32, libc::SIGKILL);
            }
        }
    }
    Ok(())
}

pub(crate) async fn resolve_link_external_url_for_output(
    provider: &LaunchedSite,
    provider_output_dir: &Path,
    link: &RunLink,
    consumer_kind: SiteKind,
    run_root: &Path,
    bridge_proxies: &mut BTreeMap<BridgeProxyKey, BridgeProxyHandle>,
) -> Result<String> {
    if !link_needs_bridge_proxy(provider.receipt.kind, consumer_kind) {
        return external_slot_url(provider, provider_output_dir, link, consumer_kind);
    }

    let port = ensure_bridge_proxy(
        run_root,
        provider,
        provider_output_dir,
        &link.export_name,
        consumer_kind,
        bridge_proxies,
    )
    .await?;
    bridge_proxy_external_url(port, link.protocol, consumer_kind)
}

pub(super) fn link_needs_bridge_proxy(provider_kind: SiteKind, consumer_kind: SiteKind) -> bool {
    matches!(consumer_kind, SiteKind::Compose | SiteKind::Kubernetes)
        && provider_kind != SiteKind::Kubernetes
}

pub(super) async fn ensure_bridge_proxy(
    run_root: &Path,
    provider: &LaunchedSite,
    provider_output_dir: &Path,
    export_name: &str,
    consumer_kind: SiteKind,
    bridge_proxies: &mut BTreeMap<BridgeProxyKey, BridgeProxyHandle>,
) -> Result<u16> {
    let key = BridgeProxyKey {
        provider_output_dir: provider_output_dir.display().to_string(),
        export_name: export_name.to_string(),
        consumer_kind,
    };
    if let Some(proxy) = bridge_proxies.get_mut(&key)
        && proxy.child.try_wait().into_diagnostic()?.is_none()
    {
        return Ok(proxy.listen.port());
    }

    let listen = bridge_proxy_bind_addr(consumer_kind, reserve_loopback_port()?);
    let child = spawn_bridge_proxy(run_root, provider, provider_output_dir, export_name, listen)?;
    wait_for_socket_listener(bridge_proxy_probe_addr(listen)).await?;
    bridge_proxies.insert(key, BridgeProxyHandle { child, listen });
    Ok(listen.port())
}

pub(super) fn spawn_bridge_proxy(
    run_root: &Path,
    provider: &LaunchedSite,
    provider_output_dir: &Path,
    export_name: &str,
    listen: SocketAddr,
) -> Result<Child> {
    let logs_root = run_root.join("bridge-proxies");
    fs::create_dir_all(&logs_root)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create {}", logs_root.display()))?;
    let log_path = logs_root.join(format!("{export_name}.log"));
    spawn_detached_child(run_root, &log_path, |cmd| {
        cmd.arg("proxy")
            .arg(provider_output_dir)
            .arg("--export")
            .arg(bridge_proxy_export_binding(export_name, listen));
        if provider.receipt.kind == SiteKind::Kubernetes {
            let control = provider.router_control.to_string();
            cmd.arg("--router-addr")
                .arg(provider.router_addr.to_string())
                .arg("--router-control-addr")
                .arg(control);
        }
    })
}

pub(super) fn bridge_proxy_export_binding(export_name: &str, listen: SocketAddr) -> String {
    format!("{export_name}={}:{}", listen.ip(), listen.port())
}

pub(super) fn bridge_proxy_bind_addr(consumer_kind: SiteKind, port: u16) -> SocketAddr {
    host_service_bind_addr_for_consumer(consumer_kind, port)
}

pub(super) fn bridge_proxy_probe_addr(listen: SocketAddr) -> SocketAddr {
    listener_probe_addr(listen)
}

pub(super) fn bridge_proxy_external_url(
    port: u16,
    protocol: NetworkProtocol,
    consumer_kind: SiteKind,
) -> Result<String> {
    let host = host_service_host_for_consumer(consumer_kind);
    Ok(match protocol {
        NetworkProtocol::Http | NetworkProtocol::Https => format!("http://{host}:{port}"),
        NetworkProtocol::Tcp => format!("tcp://{host}:{port}"),
        _ => {
            return Err(miette::miette!(
                "mixed-site bridge proxy does not support protocol `{protocol}`"
            ));
        }
    })
}

pub(crate) fn host_service_host_for_consumer(consumer_kind: SiteKind) -> String {
    match consumer_kind {
        SiteKind::Compose => CONTAINER_HOST_ALIAS.to_string(),
        SiteKind::Direct | SiteKind::Vm | SiteKind::Kubernetes => {
            container_host_for_consumer(SiteKind::Direct, consumer_kind)
        }
    }
}

pub(super) fn consumer_needs_host_wide_listener(consumer_kind: SiteKind) -> bool {
    matches!(consumer_kind, SiteKind::Compose | SiteKind::Kubernetes)
}

pub fn host_service_bind_addr_for_consumer(consumer_kind: SiteKind, port: u16) -> SocketAddr {
    host_proxy_bind_addr(consumer_needs_host_wide_listener(consumer_kind), port)
}

pub fn router_mesh_addr_for_consumer(
    provider_kind: SiteKind,
    consumer_kind: SiteKind,
    router_mesh_addr: &str,
) -> Result<String> {
    match consumer_kind {
        SiteKind::Compose | SiteKind::Kubernetes => {
            let addr = router_mesh_addr
                .parse::<SocketAddr>()
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!("invalid live router mesh address `{router_mesh_addr}`")
                })?;
            let host = container_host_for_consumer(provider_kind, consumer_kind);
            Ok(format!("{host}:{}", addr.port()))
        }
        SiteKind::Direct | SiteKind::Vm => {
            #[cfg(target_os = "linux")]
            {
                Ok(rewrite_peer_addr_for_slirp_gateway(router_mesh_addr))
            }
            #[cfg(not(target_os = "linux"))]
            {
                Ok(router_mesh_addr.to_string())
            }
        }
    }
}

pub(super) fn host_proxy_bind_addr(needs_host_wide_listener: bool, port: u16) -> SocketAddr {
    if needs_host_wide_listener {
        SocketAddr::from(([0, 0, 0, 0], port))
    } else {
        SocketAddr::from(([127, 0, 0, 1], port))
    }
}

pub(super) fn listener_probe_addr(listen: SocketAddr) -> SocketAddr {
    if listen.ip().is_unspecified() {
        SocketAddr::from(([127, 0, 0, 1], listen.port()))
    } else {
        listen
    }
}

pub(super) fn external_slot_url(
    provider: &LaunchedSite,
    provider_output_dir: &Path,
    link: &RunLink,
    consumer_kind: SiteKind,
) -> Result<String> {
    let host = container_host_for_consumer(provider.receipt.kind, consumer_kind);
    let route_id = provider_export_route_id(provider_output_dir, link)?;
    let mut mesh_url = Url::parse(&format!("mesh://{}:{}", host, provider.router_addr.port()))
        .into_diagnostic()
        .wrap_err("failed to build mesh link url")?;
    let peer_key =
        base64::engine::general_purpose::STANDARD.encode(provider.router_identity.public_key);
    mesh_url
        .query_pairs_mut()
        .append_pair("peer_id", &provider.router_identity.id)
        .append_pair("peer_key", &peer_key)
        .append_pair("route_id", &route_id)
        .append_pair("capability", &link.export_name);
    Ok(mesh_url.to_string())
}

pub(super) fn provider_export_route_id(
    provider_output_dir: &Path,
    link: &RunLink,
) -> Result<String> {
    if let Some(route_id) = load_output_proxy_metadata(provider_output_dir)?
        .exports
        .get(&link.export_name)
        .and_then(|export| export.route_id.clone())
    {
        return Ok(route_id);
    }
    Ok(router_export_route_id(
        &link.export_name,
        mesh_protocol(link.protocol)?,
    ))
}

pub(super) fn container_host_for_consumer(
    provider_kind: SiteKind,
    consumer_kind: SiteKind,
) -> String {
    let container_host_ip = container_host_ip();
    container_host_from_resolved_ip(provider_kind, consumer_kind, container_host_ip.as_deref())
}

pub(super) fn container_host_from_resolved_ip(
    provider_kind: SiteKind,
    consumer_kind: SiteKind,
    container_host_ip: Option<&str>,
) -> String {
    match consumer_kind {
        SiteKind::Direct | SiteKind::Vm => "127.0.0.1".to_string(),
        SiteKind::Compose => {
            if provider_kind == SiteKind::Kubernetes {
                container_host_ip
                    .unwrap_or(CONTAINER_HOST_ALIAS)
                    .to_string()
            } else {
                CONTAINER_HOST_ALIAS.to_string()
            }
        }
        SiteKind::Kubernetes => container_host_ip
            .unwrap_or(CONTAINER_HOST_ALIAS)
            .to_string(),
    }
}

pub(super) fn container_host_ip() -> Option<String> {
    KUBERNETES_CONTAINER_HOST_IP
        .get_or_init(resolve_container_host_ip)
        .clone()
}

pub(super) fn resolve_container_host_ip() -> Option<String> {
    if cfg!(target_os = "linux") {
        return resolve_linux_container_host_ip();
    }
    resolve_desktop_container_host_ip()
}

pub(super) fn resolve_linux_container_host_ip() -> Option<String> {
    let output = Command::new("docker")
        .arg("network")
        .arg("inspect")
        .arg("bridge")
        .arg("--format")
        .arg("{{(index .IPAM.Config 0).Gateway}}")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let host = String::from_utf8(output.stdout).ok()?.trim().to_string();
    host.parse::<std::net::IpAddr>().ok()?;
    Some(host)
}

pub(super) fn resolve_desktop_container_host_ip() -> Option<String> {
    let output = Command::new("docker")
        .arg("run")
        .arg("--rm")
        .arg("busybox:1.36.1")
        .arg("nslookup")
        .arg(CONTAINER_HOST_ALIAS)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    String::from_utf8(output.stdout)
        .ok()?
        .lines()
        .flat_map(str::split_whitespace)
        .filter_map(|token| token.parse::<std::net::Ipv4Addr>().ok())
        .map(|ip| ip.to_string())
        .next_back()
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::parse_process_status_code;

    #[cfg(unix)]
    #[test]
    fn parse_process_status_code_normalizes_unix_ps_output() {
        assert_eq!(parse_process_status_code("S+\n"), Some('S'));
        assert_eq!(parse_process_status_code("z\n"), Some('Z'));
        assert_eq!(parse_process_status_code(""), None);
    }
}
