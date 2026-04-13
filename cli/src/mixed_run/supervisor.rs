use super::*;

pub(crate) fn mixed_run_storage_root(override_root: Option<&Path>) -> Result<PathBuf> {
    let path = if let Some(root) = override_root {
        if root.is_absolute() {
            root.to_path_buf()
        } else {
            env::current_dir().into_diagnostic()?.join(root)
        }
    } else {
        env::current_dir().into_diagnostic()?.join(".amber-runs")
    };
    Ok(path)
}

pub(super) fn materialize_site_artifacts(
    sites_root: &Path,
    site_id: &str,
    site_plan: &RunSitePlan,
) -> Result<PathBuf> {
    let artifact_dir = sites_root.join(site_id).join("artifact");
    fs::create_dir_all(&artifact_dir)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create site artifact dir {}",
                artifact_dir.display()
            )
        })?;
    for (relative, contents) in &site_plan.artifact_files {
        let path = artifact_dir.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!("failed to create artifact directory {}", parent.display())
                })?;
        }
        fs::write(&path, contents)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to write site artifact {}", path.display()))?;
    }
    let scenario_ir = serde_json::to_vec_pretty(&site_plan.scenario_ir)
        .map_err(|err| miette::miette!("failed to serialize site scenario IR: {err}"))?;
    fs::write(artifact_dir.join("scenario-ir.json"), scenario_ir)
        .into_diagnostic()
        .wrap_err("failed to write site scenario IR")?;
    Ok(artifact_dir)
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

pub(super) fn external_slot_env_for_site(
    site_id: &str,
    consumer_kind: SiteKind,
    links: &[RunLink],
    launched_by_site: &BTreeMap<String, LaunchedSite>,
) -> Result<BTreeMap<String, String>> {
    let mut env = BTreeMap::new();
    for link in links {
        if link.consumer_site != site_id {
            continue;
        }
        let Some(provider) = launched_by_site.get(&link.provider_site) else {
            if link.weak {
                continue;
            }
            return Err(miette::miette!(
                "provider site `{}` has not been launched before consumer site `{site_id}`",
                link.provider_site
            ));
        };
        env.insert(
            amber_compiler::mesh::external_slot_env_var(&link.external_slot_name),
            external_slot_url(
                provider,
                Path::new(&provider.receipt.artifact_dir),
                link,
                consumer_kind,
            )?,
        );
    }
    Ok(env)
}

pub(super) fn external_slot_name_from_env_var(env_var: &str) -> String {
    let slot = env_var
        .strip_prefix("AMBER_EXTERNAL_SLOT_")
        .unwrap_or(env_var);
    slot.strip_suffix("_URL")
        .unwrap_or(slot)
        .to_ascii_lowercase()
}

pub(super) fn launch_env(
    run_id: &str,
    mesh_scope: &str,
    kind: SiteKind,
    runtime_env: &BTreeMap<String, String>,
    external_env: &BTreeMap<String, String>,
    observability_endpoint: Option<&str>,
) -> Result<BTreeMap<String, String>> {
    let mut env = merge_env_maps(runtime_env, external_env);
    env.insert(SCENARIO_RUN_ID_ENV.to_string(), run_id.to_string());
    env.insert(SCENARIO_SCOPE_ENV.to_string(), mesh_scope.to_string());
    if let Some(endpoint) = observability_endpoint {
        match kind {
            SiteKind::Direct | SiteKind::Vm => {
                env.insert(
                    "OTEL_EXPORTER_OTLP_ENDPOINT".to_string(),
                    endpoint.to_string(),
                );
            }
            SiteKind::Compose | SiteKind::Kubernetes => {
                env.insert(
                    OTELCOL_UPSTREAM_ENV.to_string(),
                    observability_endpoint_for_site(kind, endpoint)?,
                );
            }
        }
    }
    Ok(env)
}

pub(super) fn merge_env_maps(
    left: &BTreeMap<String, String>,
    right: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut merged = left.clone();
    merged.extend(right.clone());
    merged
}

pub(super) fn build_supervisor_plan(
    input: SupervisorPlanInput<'_>,
    launch_env: BTreeMap<String, String>,
) -> Result<SiteSupervisorPlan> {
    fs::create_dir_all(input.site_state_root)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create site state dir {}",
                input.site_state_root.display()
            )
        })?;

    Ok(SiteSupervisorPlan {
        schema: SITE_PLAN_SCHEMA.to_string(),
        version: SITE_PLAN_VERSION,
        run_id: input.run_id.to_string(),
        mesh_scope: input.mesh_scope.to_string(),
        run_root: input.run_root.display().to_string(),
        coordinator_pid: std::process::id(),
        site_id: input.site_id.to_string(),
        kind: input.site_plan.site.kind,
        artifact_dir: input.artifact_dir.display().to_string(),
        site_state_root: input.site_state_root.display().to_string(),
        storage_root: matches!(input.site_plan.site.kind, SiteKind::Direct | SiteKind::Vm)
            .then(|| input.site_state_root.join("storage").display().to_string()),
        runtime_root: matches!(input.site_plan.site.kind, SiteKind::Direct | SiteKind::Vm)
            .then(|| input.site_state_root.join("runtime").display().to_string()),
        router_mesh_port: if matches!(
            input.site_plan.site.kind,
            SiteKind::Direct | SiteKind::Vm | SiteKind::Compose
        ) {
            Some(reserve_loopback_port()?)
        } else {
            None
        },
        compose_project: (input.site_plan.site.kind == SiteKind::Compose)
            .then(|| compose_project_name(input.run_id, input.site_id)),
        kubernetes_namespace: (input.site_plan.site.kind == SiteKind::Kubernetes)
            .then(|| {
                prepare_kubernetes_artifact_namespace(
                    input.run_id,
                    input.site_id,
                    input.artifact_dir,
                )
            })
            .transpose()?,
        context: input.site_plan.site.context.clone(),
        port_forward_mesh_port: if input.site_plan.site.kind == SiteKind::Kubernetes {
            Some(reserve_loopback_port()?)
        } else {
            None
        },
        port_forward_control_port: if input.site_plan.site.kind == SiteKind::Kubernetes {
            Some(reserve_loopback_port()?)
        } else {
            None
        },
        observability_endpoint: input.observability_endpoint.map(ToOwned::to_owned),
        site_controller_plan_path: input
            .site_controller_plan_path
            .map(|path| path.display().to_string()),
        site_controller_url: input.site_controller_url.map(ToOwned::to_owned),
        controller_route_ports: Vec::new(),
        launch_env,
    })
}

pub(super) fn spawn_site_supervisor(site_state_root: &Path) -> Result<SupervisorChild> {
    let child = spawn_detached_child(
        site_state_root,
        &site_state_root.join("supervisor.log"),
        |cmd| {
            cmd.arg("run-site-supervisor")
                .arg("--plan")
                .arg(site_supervisor_plan_path(site_state_root));
        },
    )?;
    Ok(SupervisorChild { child })
}

pub(super) async fn wait_for_site_ready(
    site_id: &str,
    site_plan: &RunSitePlan,
    site_state_root: &Path,
    supervisor: &mut SupervisorChild,
    mesh_scope: &str,
) -> Result<LaunchedSite> {
    let deadline = Instant::now() + site_ready_timeout(site_plan);
    let state_path = site_state_path(site_state_root.parent().unwrap_or(site_state_root), site_id);
    loop {
        if state_path.is_file() {
            let state: SiteManagerState = read_json(&state_path, "site manager state")?;
            if matches!(state.status, SiteLifecycleStatus::Running) {
                let launched = launched_site_from_state(site_plan, &state, mesh_scope)?;
                if launched.router_identity.id != site_plan.router_identity_id {
                    return Err(miette::miette!(
                        "site `{site_id}` reported router identity `{}` but run plan expected `{}`",
                        launched.router_identity.id,
                        site_plan.router_identity_id
                    ));
                }
                if launched.router_identity.mesh_scope.as_deref() != Some(mesh_scope) {
                    return Err(miette::miette!(
                        "site `{site_id}` reported mesh scope `{}` but run plan expected \
                         `{mesh_scope}`",
                        launched
                            .router_identity
                            .mesh_scope
                            .as_deref()
                            .unwrap_or("<missing>")
                    ));
                }
                return Ok(launched);
            }
            if matches!(state.status, SiteLifecycleStatus::Failed) {
                return Err(miette::miette!(
                    "site `{site_id}` failed during startup: {}",
                    state
                        .last_error
                        .unwrap_or_else(|| "unknown failure".to_string())
                ));
            }
        }
        if let Some(status) = supervisor.child.try_wait().into_diagnostic()? {
            if state_path.is_file()
                && let Ok(state) = read_json::<SiteManagerState>(&state_path, "site manager state")
                && matches!(state.status, SiteLifecycleStatus::Failed)
            {
                return Err(miette::miette!(
                    "site `{site_id}` failed during startup: {}",
                    state
                        .last_error
                        .unwrap_or_else(|| "unknown failure".to_string())
                ));
            }
            return Err(miette::miette!(
                "site supervisor for `{site_id}` exited before becoming ready with status {status}"
            ));
        }
        if Instant::now() >= deadline {
            return Err(miette::miette!(
                "timed out waiting for site `{site_id}` to become ready"
            ));
        }
        sleep(Duration::from_millis(200)).await;
    }
}

pub(super) fn site_ready_timeout(site_plan: &RunSitePlan) -> Duration {
    if matches!(site_plan.site.kind, SiteKind::Vm) && vm_uses_tcg_accel() {
        TCG_VM_STARTUP_TIMEOUT
    } else {
        site_ready_timeout_for_kind(site_plan.site.kind)
    }
}

pub(crate) fn site_ready_timeout_for_kind(kind: SiteKind) -> Duration {
    match kind {
        SiteKind::Kubernetes => KUBERNETES_WORKLOAD_READY_TIMEOUT + KUBERNETES_SITE_READY_BUFFER,
        SiteKind::Direct | SiteKind::Compose | SiteKind::Vm => Duration::from_secs(120),
    }
}

pub(super) async fn register_new_site_links(
    site_id: &str,
    links: &[RunLink],
    launched: &mut LaunchedSite,
    launched_by_site: &BTreeMap<String, LaunchedSite>,
    run_root: &Path,
    state_root: &Path,
    bridge_proxies: &mut BTreeMap<BridgeProxyKey, BridgeProxyHandle>,
) -> Result<()> {
    for link in links {
        if link.consumer_site == site_id {
            let Some(provider) = launched_by_site.get(&link.provider_site) else {
                if link.weak {
                    continue;
                }
                return Err(miette::miette!(
                    "provider site `{}` is not active",
                    link.provider_site
                ));
            };
            let external_url = resolve_link_external_url(
                provider,
                link,
                launched.receipt.kind,
                run_root,
                bridge_proxies,
            )
            .await?;
            let consumer_key = base64::engine::general_purpose::STANDARD
                .encode(launched.router_identity.public_key);

            register_external_slot_with_retry(
                &launched.router_control,
                &link.external_slot_name,
                &external_url,
                ROUTER_CONTROL_TIMEOUT,
            )
            .await?;
            register_export_peer_with_retry(
                &provider.router_control,
                &link.export_name,
                &launched.router_identity.id,
                &consumer_key,
                &link.protocol.to_string(),
                Some(&router_export_route_id(
                    &link.export_name,
                    mesh_protocol(link.protocol)?,
                )),
                ROUTER_CONTROL_TIMEOUT,
            )
            .await?;

            update_desired_links_for_consumer(
                &state_root.join(site_id),
                &link.external_slot_name,
                &external_url,
            )?;
            update_desired_links_for_provider(
                &state_root.join(&link.provider_site),
                DesiredExportPeer {
                    export_name: link.export_name.clone(),
                    peer_id: launched.router_identity.id.clone(),
                    peer_key_b64: consumer_key,
                    protocol: link.protocol.to_string(),
                    route_id: Some(router_export_route_id(
                        &link.export_name,
                        mesh_protocol(link.protocol)?,
                    )),
                },
            )?;
            continue;
        }
        if link.provider_site != site_id {
            continue;
        }
        let Some(consumer) = launched_by_site.get(&link.consumer_site) else {
            continue;
        };
        let external_url = resolve_link_external_url(
            launched,
            link,
            consumer.receipt.kind,
            run_root,
            bridge_proxies,
        )
        .await?;
        let consumer_key =
            base64::engine::general_purpose::STANDARD.encode(consumer.router_identity.public_key);

        register_external_slot_with_retry(
            &consumer.router_control,
            &link.external_slot_name,
            &external_url,
            ROUTER_CONTROL_TIMEOUT,
        )
        .await?;
        register_export_peer_with_retry(
            &launched.router_control,
            &link.export_name,
            &consumer.router_identity.id,
            &consumer_key,
            &link.protocol.to_string(),
            Some(&router_export_route_id(
                &link.export_name,
                mesh_protocol(link.protocol)?,
            )),
            ROUTER_CONTROL_TIMEOUT,
        )
        .await?;

        update_desired_links_for_consumer(
            &state_root.join(&link.consumer_site),
            &link.external_slot_name,
            &external_url,
        )?;
        update_desired_links_for_provider(
            &state_root.join(site_id),
            DesiredExportPeer {
                export_name: link.export_name.clone(),
                peer_id: consumer.router_identity.id.clone(),
                peer_key_b64: consumer_key,
                protocol: link.protocol.to_string(),
                route_id: Some(router_export_route_id(
                    &link.export_name,
                    mesh_protocol(link.protocol)?,
                )),
            },
        )?;
    }
    Ok(())
}

pub(crate) fn update_desired_links_for_consumer(
    site_state_root: &Path,
    slot_name: &str,
    url: &str,
) -> Result<()> {
    let path = desired_links_path(site_state_root);
    let mut state: DesiredLinkState = if path.is_file() {
        read_json(&path, "desired links")?
    } else {
        empty_desired_link_state()
    };
    state.external_slots.insert(
        amber_compiler::mesh::external_slot_env_var(slot_name),
        url.to_string(),
    );
    write_json(&path, &state)
}

pub(crate) fn update_desired_links_for_provider(
    site_state_root: &Path,
    peer: DesiredExportPeer,
) -> Result<()> {
    let path = desired_links_path(site_state_root);
    let mut state: DesiredLinkState = if path.is_file() {
        read_json(&path, "desired links")?
    } else {
        empty_desired_link_state()
    };
    if !state.export_peers.contains(&peer) {
        state.export_peers.push(peer);
    }
    write_json(&path, &state)
}

fn empty_desired_link_state() -> DesiredLinkState {
    DesiredLinkState {
        schema: DESIRED_LINKS_SCHEMA.to_string(),
        version: DESIRED_LINKS_VERSION,
        external_slots: BTreeMap::new(),
        export_peers: Vec::new(),
        external_slot_overlays: BTreeMap::new(),
        export_peer_overlays: BTreeMap::new(),
    }
}

pub(super) fn launched_site_from_state(
    site_plan: &RunSitePlan,
    state: &SiteManagerState,
    mesh_scope: &str,
) -> Result<LaunchedSite> {
    let router_control = parse_control_endpoint(
        state
            .router_control
            .as_deref()
            .ok_or_else(|| miette::miette!("site state is missing router control"))?,
    )?;
    let router_addr = state
        .router_mesh_addr
        .as_deref()
        .ok_or_else(|| miette::miette!("site state is missing router mesh addr"))?
        .parse()
        .into_diagnostic()
        .wrap_err("invalid router mesh addr in site state")?;
    let router_identity = MeshIdentityPublic {
        id: state
            .router_identity_id
            .clone()
            .ok_or_else(|| miette::miette!("site state is missing router identity id"))?,
        public_key: decode_public_key(
            state
                .router_public_key_b64
                .as_deref()
                .ok_or_else(|| miette::miette!("site state is missing router public key"))?,
        )?,
        mesh_scope: Some(mesh_scope.to_string()),
    };
    Ok(LaunchedSite {
        receipt: SiteReceipt {
            kind: site_plan.site.kind,
            artifact_dir: state.artifact_dir.clone(),
            supervisor_pid: state.supervisor_pid,
            process_pid: state.process_pid,
            compose_project: state.compose_project.clone(),
            kubernetes_namespace: state.kubernetes_namespace.clone(),
            port_forward_pid: state.port_forward_pid,
            context: state.context.clone(),
            router_control: state.router_control.clone(),
            router_mesh_addr: state.router_mesh_addr.clone(),
            router_identity_id: state.router_identity_id.clone(),
            router_public_key_b64: state.router_public_key_b64.clone(),
            site_controller_pid: state.site_controller_pid,
            site_controller_url: state.site_controller_url.clone(),
        },
        router_control,
        router_identity,
        router_addr,
    })
}

pub(crate) fn launched_site_from_receipt(
    site_receipt: &SiteReceipt,
    mesh_scope: &str,
) -> Result<LaunchedSite> {
    let router_control = parse_control_endpoint(
        site_receipt
            .router_control
            .as_deref()
            .ok_or_else(|| miette::miette!("site receipt is missing router control"))?,
    )?;
    let router_addr = site_receipt
        .router_mesh_addr
        .as_deref()
        .ok_or_else(|| miette::miette!("site receipt is missing router mesh addr"))?
        .parse()
        .into_diagnostic()
        .wrap_err("invalid router mesh addr in site receipt")?;
    let router_identity = MeshIdentityPublic {
        id: site_receipt
            .router_identity_id
            .clone()
            .ok_or_else(|| miette::miette!("site receipt is missing router identity id"))?,
        public_key: decode_public_key(
            site_receipt
                .router_public_key_b64
                .as_deref()
                .ok_or_else(|| miette::miette!("site receipt is missing router public key"))?,
        )?,
        mesh_scope: Some(mesh_scope.to_string()),
    };
    Ok(LaunchedSite {
        receipt: site_receipt.clone(),
        router_control,
        router_identity,
        router_addr,
    })
}

pub(super) async fn ensure_site_running(
    plan: &SiteSupervisorPlan,
    runtime: &mut SupervisorRuntime,
) -> Result<()> {
    reap_child(&mut runtime.site_process)?;
    reap_child(&mut runtime.port_forward)?;
    reap_child(&mut runtime.site_controller)?;

    if matches!(plan.kind, SiteKind::Direct | SiteKind::Vm)
        && runtime.site_controller.is_none()
        && let Some(plan_path) = plan.site_controller_plan_path.as_deref()
    {
        let controller = super::site_controller_command()?;
        runtime.site_controller = Some(spawn_runtime_process_with_executable(
            &controller.executable,
            &PathBuf::from(&plan.site_state_root),
            "site-controller.log",
            &plan.launch_env,
            |cmd| {
                for arg in &controller.prefix_args {
                    cmd.arg(arg);
                }
                cmd.arg("--plan").arg(plan_path);
            },
        )?);
    }

    match plan.kind {
        SiteKind::Direct => {
            if runtime.site_process.is_none() {
                runtime.last_start_attempt = Some(Instant::now());
                runtime.ready_since = None;
                runtime.site_process = Some(spawn_runtime_process(
                    &PathBuf::from(&plan.site_state_root),
                    "site.log",
                    &plan.launch_env,
                    |cmd| {
                        cmd.arg("run-direct-init")
                            .arg("--plan")
                            .arg(PathBuf::from(&plan.artifact_dir).join("direct-plan.json"))
                            .arg("--storage-root")
                            .arg(required_path(
                                plan.storage_root.as_deref(),
                                "direct storage root",
                            ));
                        if let Some(runtime_root) = plan.runtime_root.as_deref() {
                            cmd.arg("--runtime-root").arg(runtime_root);
                        }
                        if let Some(port) = plan.router_mesh_port {
                            cmd.arg("--router-mesh-port").arg(port.to_string());
                        }
                    },
                )?);
            }
        }
        SiteKind::Vm => {
            if runtime.site_process.is_none() {
                runtime.last_start_attempt = Some(Instant::now());
                runtime.ready_since = None;
                runtime.site_process = Some(spawn_runtime_process(
                    &PathBuf::from(&plan.site_state_root),
                    "site.log",
                    &plan.launch_env,
                    |cmd| {
                        cmd.arg("run-vm-init")
                            .arg("--plan")
                            .arg(PathBuf::from(&plan.artifact_dir).join("vm-plan.json"))
                            .arg("--storage-root")
                            .arg(required_path(
                                plan.storage_root.as_deref(),
                                "vm storage root",
                            ));
                        if let Some(runtime_root) = plan.runtime_root.as_deref() {
                            cmd.arg("--runtime-root").arg(runtime_root);
                        }
                        if let Some(port) = plan.router_mesh_port {
                            cmd.arg("--router-mesh-port").arg(port.to_string());
                        }
                    },
                )?);
            }
        }
        SiteKind::Compose => {
            if !runtime.site_started {
                runtime.last_start_attempt = Some(Instant::now());
                runtime.ready_since = None;
                let output = compose_command(
                    plan.compose_project.as_deref(),
                    Path::new(&plan.artifact_dir),
                )
                .envs(plan.launch_env.clone())
                .arg("up")
                .arg("-d")
                .output()
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to start compose site `{}`", plan.site_id))?;
                if !output.status.success() {
                    return Err(compose_start_failure(&plan.site_id, &output));
                }
                runtime.site_started = true;
            }
        }
        SiteKind::Kubernetes => {
            if !runtime.site_started {
                runtime.last_start_attempt = Some(Instant::now());
                runtime.ready_since = None;
                ensure_kubernetes_namespace(plan)?;
                let status = kubectl_command(plan.context.as_deref())
                    .current_dir(&plan.artifact_dir)
                    .arg("apply")
                    .arg("-k")
                    .arg(".")
                    .status()
                    .into_diagnostic()
                    .wrap_err_with(|| {
                        format!("failed to apply kubernetes site `{}`", plan.site_id)
                    })?;
                if !status.success() {
                    return Err(miette::miette!(
                        "kubernetes site `{}` failed with status {status}",
                        plan.site_id
                    ));
                }
                ensure_kubernetes_workloads_ready(plan)?;
                runtime.site_started = true;
            }
            if runtime.port_forward.is_none() {
                runtime.ready_since = None;
                runtime.port_forward = Some(spawn_port_forward(plan)?);
            }
        }
    }
    Ok(())
}

pub(super) async fn try_discover_site(
    plan: &SiteSupervisorPlan,
    runtime: &mut SupervisorRuntime,
    stop_requested: &AtomicBool,
    run_root: &Path,
) -> Result<Option<RouterDiscovery>> {
    reap_child(&mut runtime.site_process)?;
    reap_child(&mut runtime.port_forward)?;
    let discovery = match plan.kind {
        SiteKind::Direct => try_discover_direct_site(plan, runtime, stop_requested, run_root).await,
        SiteKind::Vm => try_discover_vm_site(plan, runtime, stop_requested, run_root).await,
        SiteKind::Compose => try_discover_compose_site(plan, stop_requested, run_root).await,
        SiteKind::Kubernetes => {
            try_discover_kubernetes_site(plan, runtime, stop_requested, run_root).await
        }
    }?;
    if discovery.is_none()
        && plan.kind == SiteKind::Compose
        && !compose_site_controller_started(plan)?
    {
        runtime.site_started = false;
    }
    Ok(discovery)
}

pub(super) async fn try_discover_direct_site(
    plan: &SiteSupervisorPlan,
    runtime: &SupervisorRuntime,
    stop_requested: &AtomicBool,
    run_root: &Path,
) -> Result<Option<RouterDiscovery>> {
    let Some(_site_process) = runtime.site_process.as_ref() else {
        return Ok(None);
    };
    let artifact_dir =
        canonicalize_existing_path(Path::new(&plan.artifact_dir), "direct artifact dir")?;
    if artifact_dir
        .join(".amber")
        .join("direct-runtime.json")
        .is_file()
    {
        let state: DirectRuntimeStateView = read_json(
            &direct_runtime_state_path(&artifact_dir),
            "direct runtime state",
        )?;
        let Some(router_mesh_port) = state.router_mesh_port else {
            return Ok(None);
        };
        let control_endpoint =
            ControlEndpoint::Unix(direct_current_control_socket_path(&artifact_dir));
        let router_identity = match run_until_stop(
            run_root,
            stop_requested,
            fetch_router_identity(&control_endpoint),
        )
        .await
        {
            Ok(Some(router_identity)) => router_identity,
            Ok(None) | Err(_) => return Ok(None),
        };
        let router_addr = SocketAddr::from(([127, 0, 0, 1], router_mesh_port));
        if !local_site_controller_ready(plan, VM_LOCAL_TARGET_READY_TIMEOUT)? {
            return Ok(None);
        }
        return Ok(Some(RouterDiscovery {
            control_endpoint,
            router_identity,
            router_addr: Some(router_addr),
        }));
    }
    Ok(None)
}

pub(super) async fn try_discover_vm_site(
    plan: &SiteSupervisorPlan,
    runtime: &SupervisorRuntime,
    stop_requested: &AtomicBool,
    run_root: &Path,
) -> Result<Option<RouterDiscovery>> {
    let Some(_site_process) = runtime.site_process.as_ref() else {
        return Ok(None);
    };
    let artifact_dir =
        canonicalize_existing_path(Path::new(&plan.artifact_dir), "vm artifact dir")?;
    let state_path = artifact_dir.join(".amber").join("vm-runtime.json");
    if !state_path.is_file() {
        return Ok(None);
    }
    let state: VmRuntimeState = read_json(&state_path, "vm runtime state")?;
    let Some(router_mesh_port) = state.router_mesh_port else {
        return Ok(None);
    };
    let control_endpoint = ControlEndpoint::Unix(vm_current_control_socket_path(&artifact_dir));
    let router_identity = match run_until_stop(
        run_root,
        stop_requested,
        fetch_router_identity(&control_endpoint),
    )
    .await
    {
        Ok(Some(router_identity)) => router_identity,
        Ok(None) | Err(_) => return Ok(None),
    };
    let router_addr = SocketAddr::from(([127, 0, 0, 1], router_mesh_port));
    if !vm_component_targets_ready(plan, &artifact_dir)? {
        return Ok(None);
    }
    if !local_site_controller_ready(plan, VM_LOCAL_TARGET_READY_TIMEOUT)? {
        return Ok(None);
    }
    Ok(Some(RouterDiscovery {
        control_endpoint,
        router_identity,
        router_addr: Some(router_addr),
    }))
}

pub(super) fn vm_component_targets_ready(
    plan: &SiteSupervisorPlan,
    artifact_dir: &Path,
) -> Result<bool> {
    let runtime_root = Path::new(required_str(
        plan.runtime_root.as_deref(),
        "vm runtime root",
    )?);
    if !runtime_root.is_dir() {
        return Ok(false);
    }

    let vm_plan: VmPlan = read_json(&artifact_dir.join(VM_PLAN_FILENAME), "vm plan")?;
    for component in &vm_plan.components {
        if !mesh_config_local_targets_ready(
            &runtime_root.join(&component.mesh_config_path),
            VM_LOCAL_TARGET_READY_TIMEOUT,
        )? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) fn mesh_config_local_targets_ready(path: &Path, timeout: Duration) -> Result<bool> {
    if !path.is_file() {
        return Ok(false);
    }

    let config: MeshConfigPublic = read_json(path, "mesh config")?;
    for route in config.inbound {
        let InboundTarget::Local { port } = route.target else {
            continue;
        };
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let ready = match route.protocol {
            MeshProtocol::Http => wait_for_http_response(addr, timeout).is_ok(),
            MeshProtocol::Tcp => wait_for_stable_endpoint(addr, timeout).is_ok(),
        };
        if !ready {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) fn local_site_controller_ready(
    plan: &SiteSupervisorPlan,
    timeout: Duration,
) -> Result<bool> {
    let Some(addr) = local_site_controller_addr(plan)? else {
        return Ok(false);
    };
    Ok(wait_for_http_response(addr, timeout).is_ok())
}

pub(super) fn local_site_controller_addr(plan: &SiteSupervisorPlan) -> Result<Option<SocketAddr>> {
    let Some(url) = plan.site_controller_url.as_deref() else {
        return Ok(None);
    };
    let url = Url::parse(url)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid site controller url `{url}`"))?;
    if url.scheme() != "http" {
        return Ok(None);
    }
    let host = url.host_str().ok_or_else(|| {
        miette::miette!(
            "site controller url `{url}` for site `{}` is missing a host",
            plan.site_id
        )
    })?;
    let ip = match host {
        "localhost" => std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        _ => host.parse().into_diagnostic().wrap_err_with(|| {
            format!(
                "site controller url `{url}` for site `{}` has a non-IP host `{host}`",
                plan.site_id
            )
        })?,
    };
    if !ip.is_loopback() {
        return Ok(None);
    }
    let port = url.port_or_known_default().ok_or_else(|| {
        miette::miette!(
            "site controller url `{url}` for site `{}` is missing a port",
            plan.site_id
        )
    })?;
    Ok(Some(SocketAddr::new(ip, port)))
}

pub(super) fn compose_site_controller_container_name(plan: &SiteSupervisorPlan) -> Option<String> {
    (plan.kind == SiteKind::Compose)
        .then_some(plan.compose_project.as_deref()?)
        .map(|project| {
            format!(
                "{project}-{}-1",
                amber_site_controller::SITE_CONTROLLER_SERVICE_NAME
            )
        })
}

pub(super) fn parse_container_runtime_status(raw: &str) -> Option<(&str, Option<&str>)> {
    let mut parts = raw.split_whitespace();
    let status = parts.next()?;
    let health = parts.next();
    Some((status, health))
}

fn inspect_compose_site_controller_status(
    plan: &SiteSupervisorPlan,
) -> Result<Option<(String, Option<String>)>> {
    let Some(container_name) = compose_site_controller_container_name(plan) else {
        return Ok(None);
    };
    let output = Command::new("docker")
        .arg("inspect")
        .arg("--format")
        .arg("{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}")
        .arg(&container_name)
        .output()
        .into_diagnostic()
        .wrap_err_with(|| {
            format!("failed to inspect compose site controller container `{container_name}`")
        })?;
    if !output.status.success() {
        return Ok(None);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_container_runtime_status(&stdout)
        .map(|(status, health)| (status.to_string(), health.map(str::to_string))))
}

fn compose_site_controller_started(plan: &SiteSupervisorPlan) -> Result<bool> {
    Ok(inspect_compose_site_controller_status(plan)?
        .is_some_and(|(status, _)| matches!(status.as_str(), "created" | "running" | "restarting")))
}

fn compose_site_controller_ready(plan: &SiteSupervisorPlan) -> Result<bool> {
    Ok(
        inspect_compose_site_controller_status(plan)?.is_some_and(|(status, health)| {
            status == "running" && health.as_deref().is_none_or(|health| health == "healthy")
        }),
    )
}

pub(super) async fn try_discover_compose_site(
    plan: &SiteSupervisorPlan,
    stop_requested: &AtomicBool,
    run_root: &Path,
) -> Result<Option<RouterDiscovery>> {
    let Some(discovery) = run_until_stop(
        run_root,
        stop_requested,
        discover_router_for_output(&plan.artifact_dir, plan.compose_project.as_deref(), true),
    )
    .await
    .wrap_err_with(|| format!("compose router discovery for site `{}`", plan.site_id))?
    else {
        return Ok(None);
    };
    if !compose_site_controller_ready(plan)? {
        return Ok(None);
    }
    Ok(Some(discovery))
}

pub(super) async fn try_discover_kubernetes_site(
    plan: &SiteSupervisorPlan,
    runtime: &mut SupervisorRuntime,
    stop_requested: &AtomicBool,
    run_root: &Path,
) -> Result<Option<RouterDiscovery>> {
    if runtime.port_forward.is_none() {
        runtime.port_forward = Some(spawn_port_forward(plan)?);
        return Ok(None);
    }
    let control_port = plan
        .port_forward_control_port
        .ok_or_else(|| miette::miette!("missing kubernetes control port"))?;
    let mesh_port = plan
        .port_forward_mesh_port
        .ok_or_else(|| miette::miette!("missing kubernetes mesh port"))?;
    let control_endpoint = ControlEndpoint::Tcp(format!("127.0.0.1:{control_port}"));
    let router_identity = match run_until_stop(
        run_root,
        stop_requested,
        fetch_router_identity(&control_endpoint),
    )
    .await
    {
        Ok(Some(router_identity)) => router_identity,
        Ok(None) | Err(_) => return Ok(None),
    };
    let router_addr = SocketAddr::from(([127, 0, 0, 1], mesh_port));
    if !router_mesh_listener_ready(router_addr).await {
        return Ok(None);
    }
    Ok(Some(RouterDiscovery {
        control_endpoint,
        router_identity,
        router_addr: Some(router_addr),
    }))
}

pub(super) async fn apply_desired_links(
    plan: &SiteSupervisorPlan,
    endpoint: &ControlEndpoint,
    stop_requested: &AtomicBool,
    run_root: &Path,
) -> Result<bool> {
    let desired: DesiredLinkState = read_json(
        &desired_links_path(Path::new(&plan.site_state_root)),
        "desired links",
    )?;
    for (env_var, url) in &desired.external_slots {
        let slot = external_slot_name_from_env_var(env_var);
        if run_until_stop(
            run_root,
            stop_requested,
            register_external_slot_with_retry(endpoint, &slot, url, Duration::from_secs(2)),
        )
        .await?
        .is_none()
        {
            return Ok(false);
        }
    }
    for overlay in desired.external_slot_overlays.values() {
        if run_until_stop(
            run_root,
            stop_requested,
            register_external_slot_with_retry(
                endpoint,
                &overlay.slot_name,
                &overlay.url,
                Duration::from_secs(2),
            ),
        )
        .await?
        .is_none()
        {
            return Ok(false);
        }
    }
    for peer in &desired.export_peers {
        if run_until_stop(
            run_root,
            stop_requested,
            register_export_peer_with_retry(
                endpoint,
                &peer.export_name,
                &peer.peer_id,
                &peer.peer_key_b64,
                &peer.protocol,
                peer.route_id.as_deref(),
                Duration::from_secs(2),
            ),
        )
        .await?
        .is_none()
        {
            return Ok(false);
        }
    }
    for overlay in desired.export_peer_overlays.values() {
        if run_until_stop(
            run_root,
            stop_requested,
            register_export_peer_with_retry(
                endpoint,
                &overlay.export_name,
                &overlay.peer_id,
                &overlay.peer_key_b64,
                &overlay.protocol,
                overlay.route_id.as_deref(),
                Duration::from_secs(2),
            ),
        )
        .await?
        .is_none()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) async fn cleanup_site(
    plan: &SiteSupervisorPlan,
    runtime: &mut SupervisorRuntime,
) -> Result<()> {
    reap_child(&mut runtime.site_process)?;
    reap_child(&mut runtime.port_forward)?;
    reap_child(&mut runtime.site_controller)?;

    if let Some(child) = runtime.site_process.as_mut() {
        stop_child(child).await?;
    }
    if let Some(child) = runtime.port_forward.as_mut() {
        stop_child(child).await?;
    }
    if let Some(child) = runtime.site_controller.as_mut() {
        stop_child(child).await?;
    }
    runtime.site_process = None;
    runtime.site_started = false;
    runtime.port_forward = None;
    runtime.site_controller = None;

    match plan.kind {
        SiteKind::Compose => {
            if let Some(project_name) = plan.compose_project.as_deref() {
                let status = compose_command(Some(project_name), Path::new(&plan.artifact_dir))
                    .envs(plan.launch_env.clone())
                    .arg("down")
                    .arg("-v")
                    .arg("--remove-orphans")
                    .status()
                    .into_diagnostic()
                    .wrap_err_with(|| format!("failed to stop compose site `{}`", plan.site_id))?;
                if !status.success() {
                    return Err(miette::miette!(
                        "compose site `{}` failed to stop with status {status}",
                        plan.site_id
                    ));
                }
            }
        }
        SiteKind::Kubernetes => {
            if let Some(namespace) = plan.kubernetes_namespace.as_deref() {
                let status = kubectl_command(plan.context.as_deref())
                    .arg("delete")
                    .arg("namespace")
                    .arg(namespace)
                    .arg("--ignore-not-found")
                    .status()
                    .into_diagnostic()
                    .wrap_err_with(|| {
                        format!("failed to stop kubernetes site `{}`", plan.site_id)
                    })?;
                if !status.success() {
                    return Err(miette::miette!(
                        "kubernetes site `{}` failed to stop with status {status}",
                        plan.site_id
                    ));
                }
            }
        }
        SiteKind::Direct | SiteKind::Vm => {}
    }
    cleanup_dynamic_site_children(Path::new(&plan.site_state_root), plan.kind)?;
    Ok(())
}

pub(super) fn build_site_state(
    plan: &SiteSupervisorPlan,
    runtime: &SupervisorRuntime,
    status: SiteLifecycleStatus,
    discovery: Option<&RouterDiscovery>,
    last_error: Option<String>,
) -> SiteManagerState {
    let (router_control, router_mesh_addr, router_identity_id, router_public_key_b64) =
        if let Some(discovery) = discovery {
            (
                Some(discovery.control_endpoint.to_string()),
                discovery.router_addr.map(|addr| addr.to_string()),
                Some(discovery.router_identity.id.clone()),
                Some(
                    base64::engine::general_purpose::STANDARD
                        .encode(discovery.router_identity.public_key),
                ),
            )
        } else {
            (None, None, None, None)
        };
    SiteManagerState {
        schema: SITE_STATE_SCHEMA.to_string(),
        version: SITE_STATE_VERSION,
        run_id: plan.run_id.clone(),
        site_id: plan.site_id.clone(),
        kind: plan.kind,
        status,
        artifact_dir: plan.artifact_dir.clone(),
        supervisor_pid: std::process::id(),
        process_pid: runtime.site_process.as_ref().map(Child::id),
        compose_project: plan.compose_project.clone(),
        kubernetes_namespace: plan.kubernetes_namespace.clone(),
        port_forward_pid: runtime.port_forward.as_ref().map(Child::id),
        context: plan.context.clone(),
        router_control,
        router_mesh_addr,
        router_identity_id,
        router_public_key_b64,
        site_controller_pid: runtime.site_controller.as_ref().map(Child::id),
        site_controller_url: plan.site_controller_url.clone(),
        last_error,
    }
}

pub(super) fn persist_site_state(
    state_root: &Path,
    site_id: &str,
    launched: &LaunchedSite,
    status: SiteLifecycleStatus,
    last_error: Option<String>,
) -> Result<()> {
    write_site_state(
        &site_state_path(state_root, site_id),
        SiteManagerState {
            schema: SITE_STATE_SCHEMA.to_string(),
            version: SITE_STATE_VERSION,
            run_id: state_root
                .parent()
                .and_then(|path| path.file_name())
                .and_then(|name| name.to_str())
                .unwrap_or_default()
                .to_string(),
            site_id: site_id.to_string(),
            kind: launched.receipt.kind,
            status,
            artifact_dir: launched.receipt.artifact_dir.clone(),
            supervisor_pid: launched.receipt.supervisor_pid,
            process_pid: launched.receipt.process_pid,
            compose_project: launched.receipt.compose_project.clone(),
            kubernetes_namespace: launched.receipt.kubernetes_namespace.clone(),
            port_forward_pid: launched.receipt.port_forward_pid,
            context: launched.receipt.context.clone(),
            router_control: launched.receipt.router_control.clone(),
            router_mesh_addr: launched.receipt.router_mesh_addr.clone(),
            router_identity_id: launched.receipt.router_identity_id.clone(),
            router_public_key_b64: launched.receipt.router_public_key_b64.clone(),
            site_controller_pid: launched.receipt.site_controller_pid,
            site_controller_url: launched.receipt.site_controller_url.clone(),
            last_error,
        },
    )
}

pub(super) fn write_site_state(path: &Path, state: SiteManagerState) -> Result<()> {
    write_json(path, &state)
}

pub(super) fn write_site_state_if_changed(
    path: &Path,
    last_written_state: &mut Option<SiteManagerState>,
    state: SiteManagerState,
) -> Result<()> {
    if last_written_state.as_ref() == Some(&state) {
        return Ok(());
    }
    write_site_state(path, state.clone())?;
    *last_written_state = Some(state);
    Ok(())
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

pub(super) fn compose_start_failure(
    site_id: &str,
    output: &std::process::Output,
) -> miette::Report {
    let detail = command_failure_detail(output);
    if docker_daemon_unavailable(&detail) {
        if detail.is_empty() {
            miette::miette!(
                "compose site `{site_id}` could not reach Docker. Start Docker Desktop or the \
                 Docker daemon, then try again."
            )
        } else {
            miette::miette!(
                "compose site `{site_id}` could not reach Docker. Start Docker Desktop or the \
                 Docker daemon, then try again.\n  detail: {detail}"
            )
        }
    } else if detail.is_empty() {
        miette::miette!(
            "compose site `{site_id}` failed to start with status {}",
            output.status
        )
    } else {
        miette::miette!("compose site `{site_id}` failed to start: {detail}")
    }
}

fn command_failure_detail(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    stderr
        .lines()
        .chain(stdout.lines())
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or_default()
        .to_string()
}

fn docker_daemon_unavailable(detail: &str) -> bool {
    let detail = detail.to_ascii_lowercase();
    detail.contains("cannot connect to the docker daemon")
        || detail.contains("is the docker daemon running")
        || detail.contains("docker desktop is not running")
        || detail.contains("cannot connect to the docker desktop linux vm")
}

pub(super) fn read_compose_launch_env(
    run_root: &Path,
    site_id: &str,
) -> Result<BTreeMap<String, String>> {
    let plan_path = site_supervisor_plan_path(&run_root.join("state").join(site_id));
    if !plan_path.is_file() {
        return Ok(BTreeMap::new());
    }
    let plan: SiteSupervisorPlan = read_json(&plan_path, "site supervisor plan")?;
    Ok(plan.launch_env)
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
    let deadline = Instant::now() + KUBERNETES_NAMESPACE_READY_TIMEOUT;
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
            if stderr.contains("context") && stderr.contains("does not exist") {
                let context = context.unwrap_or("<current>");
                return Err(miette::miette!(
                    "kubernetes context `{context}` is not available: {stderr}"
                ));
            }
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
                "failed to prepare kubernetes namespace `{namespace}` within {}s{detail}",
                KUBERNETES_NAMESPACE_READY_TIMEOUT.as_secs()
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

fn wait_for_named_kubernetes_resources(
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

fn wait_for_named_kubernetes_resource(
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

pub(super) fn compose_project_name(run_id: &str, site_id: &str) -> String {
    let mut out = String::from("amber_");
    for ch in format!("{run_id}_{site_id}").chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    out
}

pub(crate) fn spawn_detached_child(
    work_dir: &Path,
    log_path: &Path,
    build: impl FnOnce(&mut Command),
) -> Result<Child> {
    #[cfg(unix)]
    use std::os::unix::process::CommandExt as _;

    let exe = super::amber_cli_executable()?;
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

pub(super) fn spawn_runtime_process(
    site_state_root: &Path,
    log_name: &str,
    extra_env: &BTreeMap<String, String>,
    build: impl FnOnce(&mut Command),
) -> Result<Child> {
    let exe = super::amber_cli_executable()?;
    spawn_runtime_process_with_executable(&exe, site_state_root, log_name, extra_env, build)
}

pub(super) fn spawn_runtime_process_with_executable(
    executable: &Path,
    site_state_root: &Path,
    log_name: &str,
    extra_env: &BTreeMap<String, String>,
    build: impl FnOnce(&mut Command),
) -> Result<Child> {
    let log_path = site_state_root.join(log_name);
    let log = fs::File::create(&log_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create {}", log_path.display()))?;
    let log_err = log
        .try_clone()
        .into_diagnostic()
        .wrap_err("failed to clone site log")?;
    let mut cmd = Command::new(executable);
    cmd.envs(extra_env);
    cmd.stdout(Stdio::from(log));
    cmd.stderr(Stdio::from(log_err));
    build(&mut cmd);
    cmd.spawn()
        .into_diagnostic()
        .wrap_err("failed to spawn runtime child")
}

pub(super) fn spawn_port_forward(plan: &SiteSupervisorPlan) -> Result<Child> {
    let log_path = Path::new(&plan.site_state_root).join("port-forward.log");
    let log = fs::File::create(&log_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create {}", log_path.display()))?;
    let log_err = log
        .try_clone()
        .into_diagnostic()
        .wrap_err("failed to clone port-forward log")?;
    let namespace = required_str(plan.kubernetes_namespace.as_deref(), "kubernetes namespace")?;
    let mesh_port = plan
        .port_forward_mesh_port
        .ok_or_else(|| miette::miette!("missing kubernetes mesh forward port"))?;
    let control_port = plan
        .port_forward_control_port
        .ok_or_else(|| miette::miette!("missing kubernetes control forward port"))?;
    let mut cmd = kubectl_command(plan.context.as_deref());
    cmd.arg("-n")
        .arg(namespace)
        .arg("port-forward")
        .arg("--address")
        // Compose and VM consumers reach host-forwarded Kubernetes mesh ports via
        // host.docker.internal, so the forward must listen beyond loopback.
        .arg("0.0.0.0")
        .arg("deploy/amber-router")
        .arg(format!("{mesh_port}:24000"))
        .arg(format!("{control_port}:24100"));
    for port in &plan.controller_route_ports {
        cmd.arg(format!("{port}:{port}"));
    }
    cmd.stdout(Stdio::from(log)).stderr(Stdio::from(log_err));
    cmd.spawn()
        .into_diagnostic()
        .wrap_err("failed to spawn kubectl port-forward")
}

pub(super) fn required_path<'a>(value: Option<&'a str>, label: &str) -> &'a str {
    value.unwrap_or_else(|| panic!("missing {label}"))
}

pub(super) fn required_str<'a>(value: Option<&'a str>, label: &str) -> Result<&'a str> {
    value.ok_or_else(|| miette::miette!("missing {label}"))
}

pub(super) fn should_attempt_launch(last_start_attempt: Option<Instant>) -> bool {
    last_start_attempt.is_none_or(|instant| instant.elapsed() >= RESTART_BACKOFF)
}

pub(super) fn should_refresh_stitching(last_refresh: Option<Instant>) -> bool {
    last_refresh.is_none_or(|instant| instant.elapsed() >= STITCH_REFRESH_INTERVAL)
}

pub(super) fn reap_child(child: &mut Option<Child>) -> Result<()> {
    let Some(process) = child.as_mut() else {
        return Ok(());
    };
    if process.try_wait().into_diagnostic()?.is_some() {
        *child = None;
    }
    Ok(())
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

pub(crate) async fn resolve_link_external_url(
    provider: &LaunchedSite,
    link: &RunLink,
    consumer_kind: SiteKind,
    run_root: &Path,
    bridge_proxies: &mut BTreeMap<BridgeProxyKey, BridgeProxyHandle>,
) -> Result<String> {
    resolve_link_external_url_for_output(
        provider,
        Path::new(&provider.receipt.artifact_dir),
        link,
        consumer_kind,
        run_root,
        bridge_proxies,
    )
    .await
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
    bridge_proxies.insert(
        key,
        BridgeProxyHandle {
            child,
            export_name: export_name.to_string(),
            listen,
        },
    );
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

pub(crate) fn host_service_bind_addr_for_consumer(
    consumer_kind: SiteKind,
    port: u16,
) -> SocketAddr {
    host_proxy_bind_addr(consumer_needs_host_wide_listener(consumer_kind), port)
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

fn provider_export_route_id(provider_output_dir: &Path, link: &RunLink) -> Result<String> {
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
