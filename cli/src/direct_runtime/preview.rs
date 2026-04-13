use super::*;

pub(crate) fn component_program_spec(
    runtime_root: &Path,
    storage_root: &Path,
    component: &DirectComponentPlan,
    runtime_addresses: &DirectRuntimeAddressPlan,
    runtime_state: &DirectRuntimeState,
) -> Result<ProcessSpec> {
    #[cfg(target_os = "linux")]
    let source_dir = component_source_dir(component)?;
    let work_dir = runtime_root.join(&component.program.work_dir);
    let mut writable_dirs = vec![work_dir.clone()];
    let dynamic_caps_api_url = runtime_state
        .dynamic_caps_port_by_component
        .get(&component.id)
        .map(|port| format!("http://127.0.0.1:{port}"));
    #[cfg(target_os = "linux")]
    let read_only_mounts = component_program_read_only_mounts(component, source_dir.as_deref())?;
    let bind_mounts = direct_storage_bind_mounts(storage_root, component)?;
    match &component.program.execution {
        DirectProgramExecutionPlan::Direct { entrypoint, env } => {
            let (program, args) = split_entrypoint(entrypoint)?;
            let program =
                ensure_absolute_direct_program_path(&program, component.moniker.as_str())?;
            let mut env = env.clone();
            if let Some(url) = dynamic_caps_api_url.as_ref() {
                env.insert(
                    amber_mesh::DYNAMIC_CAPS_API_URL_ENV.to_string(),
                    url.clone(),
                );
            }
            Ok(ProcessSpec {
                name: component.program.log_name.clone(),
                program,
                args,
                env,
                work_dir,
                sandbox: ProcessSandbox::Sandboxed,
                drop_all_caps: false,
                #[cfg(target_os = "linux")]
                read_only_mounts,
                writable_dirs,
                bind_dirs: Vec::new(),
                bind_mounts,
                hidden_paths: Vec::new(),
                network: ProcessNetwork::Host,
            })
        }
        DirectProgramExecutionPlan::HelperRunner {
            entrypoint_b64,
            env_b64,
            template_spec_b64,
            runtime_config,
            mount_spec_b64,
        } => {
            let helper_binary = resolve_runtime_binary("amber-helper")?;
            let mut env = BTreeMap::new();
            let runtime_template_context =
                build_runtime_template_context(runtime_addresses, runtime_state)?;
            if let Some(value) = entrypoint_b64.as_ref() {
                env.insert("AMBER_RESOLVED_ENTRYPOINT_B64".to_string(), value.clone());
            }
            if let Some(value) = env_b64.as_ref() {
                env.insert("AMBER_RESOLVED_ENV_B64".to_string(), value.clone());
            }
            if let Some(value) = template_spec_b64.as_ref() {
                env.insert("AMBER_TEMPLATE_SPEC_B64".to_string(), value.clone());
            }
            if let Some(value) = mount_spec_b64.as_ref() {
                env.insert("AMBER_MOUNT_SPEC_B64".to_string(), value.clone());
            }
            if let Some(payload) = runtime_config {
                append_runtime_config_env(&mut env, payload)?;
            }
            append_runtime_template_context_env(&mut env, &runtime_template_context)?;
            if let Some(url) = dynamic_caps_api_url.as_ref() {
                env.insert(
                    amber_mesh::DYNAMIC_CAPS_API_URL_ENV.to_string(),
                    url.clone(),
                );
            }
            if let Some(b64) = mount_spec_b64 {
                writable_dirs.extend(decode_mount_parent_dirs(
                    b64,
                    runtime_config.as_ref(),
                    &runtime_template_context,
                    &env,
                )?);
            }
            Ok(ProcessSpec {
                name: component.program.log_name.clone(),
                program: helper_binary.to_string(),
                args: vec!["run".to_string()],
                env,
                work_dir,
                sandbox: ProcessSandbox::Sandboxed,
                drop_all_caps: false,
                #[cfg(target_os = "linux")]
                read_only_mounts,
                writable_dirs,
                bind_dirs: Vec::new(),
                bind_mounts,
                hidden_paths: Vec::new(),
                network: ProcessNetwork::Host,
            })
        }
    }
}

pub(crate) fn build_direct_site_launch_preview(
    plan_path: &Path,
    storage_root: &Path,
    runtime_root: &Path,
    router_mesh_port: Option<u16>,
) -> Result<DirectSiteLaunchPreview> {
    let plan_path = canonicalize_user_path(plan_path, "direct plan")?;
    let DirectRuntimeInputs {
        plan_root,
        direct_plan,
        mesh_plan,
    } = load_direct_runtime_inputs(&plan_path)?;
    let mut inspectability_warnings = Vec::new();
    let runtime_state = match materialize_direct_runtime(
        &plan_root,
        runtime_root,
        &direct_plan,
        &mesh_plan,
        router_mesh_port,
        true,
    ) {
        Ok(runtime_state) => {
            #[cfg(target_os = "linux")]
            configure_direct_mesh_network(runtime_root, &runtime_state, &direct_plan)?;
            #[cfg(not(target_os = "linux"))]
            configure_direct_mesh_network(runtime_root, &runtime_state, &direct_plan)?;
            runtime_state
        }
        Err(err) if missing_existing_peer_identity(&err) => {
            // Dry-run preview can still show the local process shape before peer-site routers
            // exist; the missing identities only block full mesh config materialization.
            inspectability_warnings.push(format!(
                "preview is missing one or more peer-site router identities, so mesh configs \
                 remain unresolved until those sites are running: {err}"
            ));
            let (preview_peer_identities, preview_peer_ports) =
                preview_placeholder_peer_mesh_state(&mesh_plan);
            materialize_direct_runtime_with_existing(
                &plan_root,
                runtime_root,
                &direct_plan,
                &mesh_plan,
                router_mesh_port,
                DirectExistingMeshState {
                    reuse_existing: false,
                    peer_ports_by_id: &preview_peer_ports,
                    peer_identities_by_id: &preview_peer_identities,
                },
            )?
        }
        Err(err) => return Err(err),
    };

    let router_binary = resolve_runtime_binary("amber-router")?;
    let mut processes = Vec::new();
    let mut router_public_key_b64 = None;
    if let Some(router) = direct_plan.router.as_ref() {
        let router_config_path = runtime_root.join(&router.mesh_config_path);
        match read_mesh_config_public(&router_config_path) {
            Ok(router_config) => {
                router_public_key_b64 = Some(
                    base64::engine::general_purpose::STANDARD
                        .encode(router_config.identity.public_key),
                );
            }
            Err(err) => inspectability_warnings.push(format!(
                "failed to inspect direct router mesh config {}: {err}",
                router_config_path.display()
            )),
        }
        let paths = DirectControlSocketPaths {
            artifact_link: resolve_direct_artifact_path(&plan_root, &router.control_socket_path),
            current_link: direct_current_control_socket_path(&plan_root),
            runtime: direct_runtime_control_socket_path(runtime_root),
        };
        let mut env = BTreeMap::new();
        env.insert(
            "AMBER_ROUTER_CONFIG_PATH".to_string(),
            runtime_root
                .join(&router.mesh_config_path)
                .display()
                .to_string(),
        );
        env.insert(
            "AMBER_ROUTER_IDENTITY_PATH".to_string(),
            runtime_root
                .join(&router.mesh_identity_path)
                .display()
                .to_string(),
        );
        env.insert(
            "AMBER_ROUTER_CONTROL_SOCKET_PATH".to_string(),
            paths.runtime.display().to_string(),
        );
        for passthrough in &router.env_passthrough {
            if let Ok(value) = env::var(passthrough) {
                env.insert(passthrough.clone(), value);
            }
        }
        let work_dir = runtime_root.join("work/router");
        processes.push(direct_process_preview(
            ProcessSpec {
                name: "router".to_string(),
                program: router_binary.clone(),
                args: Vec::new(),
                env,
                work_dir,
                sandbox: ProcessSandbox::Unsandboxed,
                drop_all_caps: true,
                #[cfg(target_os = "linux")]
                read_only_mounts: vec![ReadOnlyMount {
                    source: runtime_root.join("mesh"),
                    dest: runtime_root.join("mesh"),
                }],
                writable_dirs: Vec::new(),
                bind_dirs: vec![
                    direct_runtime_control_socket_path(runtime_root)
                        .parent()
                        .ok_or_else(|| {
                            miette::miette!("invalid direct runtime control socket path")
                        })?
                        .to_path_buf(),
                ],
                bind_mounts: Vec::new(),
                hidden_paths: Vec::new(),
                network: ProcessNetwork::Host,
            },
            "router",
            None,
            None,
            None,
        ));
    }

    let components_by_id = direct_plan
        .components
        .iter()
        .map(|component| (component.id, component))
        .collect::<HashMap<_, _>>();
    for component in &direct_plan.components {
        let mut env = BTreeMap::new();
        env.insert(
            "AMBER_ROUTER_CONFIG_PATH".to_string(),
            runtime_root
                .join(&component.sidecar.mesh_config_path)
                .display()
                .to_string(),
        );
        env.insert(
            "AMBER_ROUTER_IDENTITY_PATH".to_string(),
            runtime_root
                .join(&component.sidecar.mesh_identity_path)
                .display()
                .to_string(),
        );
        for passthrough in &component.sidecar.env_passthrough {
            if let Ok(value) = env::var(passthrough) {
                #[cfg(target_os = "linux")]
                let value =
                    rewrite_sidecar_env_passthrough_for_slirp(passthrough.as_str(), value.as_str());
                env.insert(passthrough.clone(), value);
            }
        }
        processes.push(direct_process_preview(
            ProcessSpec {
                name: component.sidecar.log_name.clone(),
                program: router_binary.clone(),
                args: Vec::new(),
                env,
                work_dir: runtime_root.join(&component.program.work_dir),
                sandbox: ProcessSandbox::Sandboxed,
                drop_all_caps: true,
                #[cfg(target_os = "linux")]
                read_only_mounts: vec![ReadOnlyMount {
                    source: runtime_root.join("mesh"),
                    dest: runtime_root.join("mesh"),
                }],
                writable_dirs: Vec::new(),
                bind_dirs: Vec::new(),
                bind_mounts: Vec::new(),
                hidden_paths: Vec::new(),
                network: {
                    #[cfg(target_os = "linux")]
                    {
                        ProcessNetwork::Isolated
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        ProcessNetwork::Host
                    }
                },
            },
            "sidecar",
            Some(component.moniker.as_str()),
            None,
            None,
        ));
    }
    for component_id in &direct_plan.startup_order {
        let component = components_by_id.get(component_id).copied().ok_or_else(|| {
            miette::miette!(
                "direct plan startup order references unknown component id {}",
                component_id
            )
        })?;
        let mut spec = component_program_spec(
            runtime_root,
            storage_root,
            component,
            &direct_plan.runtime_addresses,
            &runtime_state,
        )?;
        spec.hidden_paths.push(runtime_root.join("mesh"));
        let resolved_process = match &component.program.execution {
            DirectProgramExecutionPlan::Direct { .. } => None,
            DirectProgramExecutionPlan::HelperRunner { .. } => {
                Some(direct_resolved_process_preview(&spec.env)?)
            }
        };
        processes.push(direct_process_preview(
            spec,
            "program",
            Some(component.moniker.as_str()),
            Some(direct_program_network_override()),
            resolved_process,
        ));
    }

    Ok(DirectSiteLaunchPreview {
        router_public_key_b64,
        processes,
        inspectability_warnings,
    })
}

fn missing_existing_peer_identity(err: &miette::Report) -> bool {
    err.to_string()
        .contains("mesh provision plan requires existing peer identity")
}

fn preview_placeholder_peer_mesh_state(
    mesh_plan: &MeshProvisionPlan,
) -> (BTreeMap<String, MeshIdentityPublic>, BTreeMap<String, u16>) {
    let target_ids = mesh_plan
        .targets
        .iter()
        .map(|target| target.config.identity.id.as_str())
        .collect::<BTreeSet<_>>();
    let mesh_scope = mesh_plan
        .targets
        .first()
        .and_then(|target| target.config.identity.mesh_scope.clone());
    let peer_ids = mesh_plan
        .targets
        .iter()
        .flat_map(|target| target.config.peers.iter())
        .filter(|peer| !target_ids.contains(peer.id.as_str()))
        .map(|peer| peer.id.clone())
        .collect::<BTreeSet<_>>();
    let peer_identities = peer_ids
        .iter()
        .map(|peer| {
            let identity = MeshIdentity::generate(peer.clone(), mesh_scope.clone());
            (
                peer.clone(),
                MeshIdentityPublic {
                    id: identity.id,
                    public_key: identity.public_key,
                    mesh_scope: identity.mesh_scope,
                },
            )
        })
        .collect();
    let peer_ports = peer_ids
        .into_iter()
        .enumerate()
        .map(|(index, peer_id)| (peer_id, 39_000 + index as u16))
        .collect();
    (peer_identities, peer_ports)
}

pub(crate) fn load_direct_runtime_inputs(plan_path: &Path) -> Result<DirectRuntimeInputs> {
    let plan_root = plan_path
        .parent()
        .ok_or_else(|| miette::miette!("invalid direct plan path {}", plan_path.display()))?
        .to_path_buf();
    let plan_raw = fs::read_to_string(plan_path)
        .map_err(|err| miette::miette!("failed to read {}: {err}", plan_path.display()))?;
    let direct_plan: DirectPlan = serde_json::from_str(&plan_raw)
        .map_err(|err| miette::miette!("invalid direct plan {}: {err}", plan_path.display()))?;
    if direct_plan.version != DIRECT_PLAN_VERSION {
        return Err(miette::miette!(
            "unsupported direct plan version {} in {}; expected {}",
            direct_plan.version,
            plan_path.display(),
            DIRECT_PLAN_VERSION
        ));
    }
    let mesh_plan_path = plan_root.join(&direct_plan.mesh_provision_plan);
    let mesh_raw = fs::read_to_string(&mesh_plan_path)
        .map_err(|err| miette::miette!("failed to read {}: {err}", mesh_plan_path.display()))?;
    let mesh_plan: MeshProvisionPlan = serde_json::from_str(&mesh_raw).map_err(|err| {
        miette::miette!(
            "invalid mesh provision plan {}: {err}",
            mesh_plan_path.display()
        )
    })?;
    Ok(DirectRuntimeInputs {
        plan_root,
        direct_plan,
        mesh_plan,
    })
}

pub(crate) fn direct_process_preview(
    spec: ProcessSpec,
    role: &str,
    component: Option<&str>,
    network_override: Option<&str>,
    resolved_process: Option<DirectResolvedProcessPreview>,
) -> DirectLaunchProcessPreview {
    let mut argv = Vec::with_capacity(1 + spec.args.len());
    argv.push(spec.program.clone());
    argv.extend(spec.args.clone());
    DirectLaunchProcessPreview {
        role: role.to_string(),
        component: component.map(ToOwned::to_owned),
        name: spec.name,
        argv,
        env: spec.env,
        current_dir: spec.work_dir.display().to_string(),
        sandbox: match spec.sandbox {
            ProcessSandbox::Sandboxed => "sandboxed",
            ProcessSandbox::Unsandboxed => "unsandboxed",
        }
        .to_string(),
        network: network_override
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| direct_process_network_label(spec.network)),
        writable_dirs: spec
            .writable_dirs
            .into_iter()
            .map(|path| path.display().to_string())
            .collect(),
        bind_dirs: spec
            .bind_dirs
            .into_iter()
            .map(|path| path.display().to_string())
            .collect(),
        bind_mounts: spec
            .bind_mounts
            .into_iter()
            .map(|mount| DirectMountPreview {
                source: mount.source.display().to_string(),
                dest: mount.dest.display().to_string(),
            })
            .collect(),
        hidden_paths: spec
            .hidden_paths
            .into_iter()
            .map(|path| path.display().to_string())
            .collect(),
        #[cfg(target_os = "linux")]
        read_only_mounts: spec
            .read_only_mounts
            .into_iter()
            .map(|mount| DirectMountPreview {
                source: mount.source.display().to_string(),
                dest: mount.dest.display().to_string(),
            })
            .collect(),
        resolved_process,
    }
}

pub(crate) fn direct_process_network_label(network: ProcessNetwork) -> String {
    match network {
        ProcessNetwork::Host => "host".to_string(),
        #[cfg(target_os = "linux")]
        ProcessNetwork::Isolated => "isolated".to_string(),
        #[cfg(target_os = "linux")]
        ProcessNetwork::Join(_) => "join_component_sidecar".to_string(),
    }
}

pub(crate) fn direct_program_network_override() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "join_component_sidecar"
    }
    #[cfg(not(target_os = "linux"))]
    {
        "host"
    }
}

pub(crate) fn direct_resolved_process_preview(
    env_map: &BTreeMap<String, String>,
) -> Result<DirectResolvedProcessPreview> {
    let plan = amber_helper::build_run_plan(env_map.iter().map(|(key, value)| {
        (
            std::ffi::OsString::from(key),
            std::ffi::OsString::from(value),
        )
    }))
    .map_err(|err| miette::miette!("failed to build helper-runner preview: {err}"))?;
    Ok(DirectResolvedProcessPreview {
        argv: plan.entrypoint,
        env: plan
            .env
            .into_iter()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.to_string_lossy().into_owned(),
                )
            })
            .collect::<BTreeMap<_, _>>(),
        docker_mount_proxies: plan
            .docker_mount_proxies
            .into_iter()
            .map(|(path, tcp_host, tcp_port)| DirectDockerMountProxyPreview {
                path,
                tcp_host,
                tcp_port,
            })
            .collect(),
    })
}

pub(crate) fn direct_storage_bind_mounts(
    storage_root: &Path,
    component: &DirectComponentPlan,
) -> Result<Vec<BindMount>> {
    let mut mounts = Vec::new();
    for mount in &component.program.storage_mounts {
        let source = storage_root.join(&mount.state_subdir);
        fs::create_dir_all(&source)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "failed to create persistent storage directory {} for component {}",
                    source.display(),
                    component.moniker
                )
            })?;
        mounts.push(BindMount {
            source,
            dest: PathBuf::from(&mount.mount_path),
        });
    }
    Ok(mounts)
}

pub(crate) fn component_local_target_ports(
    component: &DirectComponentPlan,
    runtime_root: &Path,
) -> Result<BTreeSet<u16>> {
    let config = read_mesh_config_public(&runtime_root.join(&component.sidecar.mesh_config_path))?;
    Ok(config
        .inbound
        .into_iter()
        .filter_map(|route| match route.target {
            InboundTarget::Local { port } => Some(port),
            _ => None,
        })
        .collect())
}

#[cfg(not(target_os = "linux"))]
pub(crate) async fn wait_for_component_local_targets(
    component: &DirectComponentPlan,
    runtime_root: &Path,
    _sidecar_pid: Option<u32>,
    timeout: Duration,
) -> Result<()> {
    for port in component_local_target_ports(component, runtime_root)? {
        wait_for_stable_endpoint(SocketAddr::from(([127, 0, 0, 1], port)), timeout).map_err(
            |err| {
                miette::miette!(
                    "local target 127.0.0.1:{} for component {} did not become ready: {err}",
                    port,
                    component.moniker
                )
            },
        )?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) async fn wait_for_component_local_targets(
    component: &DirectComponentPlan,
    runtime_root: &Path,
    sidecar_pid: Option<u32>,
    timeout: Duration,
) -> Result<()> {
    let ports = component_local_target_ports(component, runtime_root)?;
    if ports.is_empty() {
        return Ok(());
    }
    let sidecar_pid = sidecar_pid.ok_or_else(|| {
        miette::miette!(
            "missing sidecar pid while waiting for component {} local targets",
            component.moniker
        )
    })?;
    let namespace_join = prepare_linux_namespace_join(sidecar_pid)?;
    let amber_cli = env::current_exe()
        .into_diagnostic()
        .wrap_err("failed to locate current amber binary for direct local probe")?;
    let deadline = Instant::now() + timeout;
    for port in ports {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(miette::miette!(
                "local target 127.0.0.1:{port} for component {} did not become ready within {:?}",
                component.moniker,
                timeout
            ));
        }
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let mut command = TokioCommand::new(&amber_cli);
        command
            .arg("run-direct-local-probe")
            .arg(addr.to_string())
            .arg("--timeout-ms")
            .arg(remaining.as_millis().to_string());
        if let Some(namespace_join) = namespace_join.clone() {
            unsafe {
                command.pre_exec(move || enter_linux_namespaces(&namespace_join));
            }
        }
        let status = command.status().await.into_diagnostic().wrap_err_with(|| {
            format!(
                "failed to start direct local readiness probe for component {}",
                component.moniker
            )
        })?;
        if !status.success() {
            return Err(miette::miette!(
                "local target {} for component {} did not become ready (status: {})",
                addr,
                component.moniker,
                status
            ));
        }
    }
    Ok(())
}

pub(crate) async fn wait_for_direct_mesh_endpoints(
    runtime_state: &DirectRuntimeState,
    timeout: Duration,
) -> Result<()> {
    let mut ports = BTreeSet::new();
    if let Some(port) = runtime_state.router_mesh_port {
        ports.insert(port);
    }
    ports.extend(runtime_state.component_mesh_port_by_id.values().copied());

    for port in ports {
        wait_for_stable_endpoint(SocketAddr::from(([127, 0, 0, 1], port)), timeout).map_err(
            |err| {
                miette::miette!("direct mesh endpoint 127.0.0.1:{port} did not become ready: {err}")
            },
        )?;
    }
    Ok(())
}

pub(crate) fn append_runtime_template_context_env(
    env_map: &mut BTreeMap<String, String>,
    context: &RuntimeTemplateContext,
) -> Result<()> {
    if context.slots_by_scope.is_empty() && context.slot_items_by_scope.is_empty() {
        return Ok(());
    }

    let encoded =
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&context).map_err(
            |err| miette::miette!("failed to serialize direct runtime template context: {err}"),
        )?);
    env_map.insert("AMBER_RUNTIME_TEMPLATE_CONTEXT_B64".to_string(), encoded);
    Ok(())
}

pub(crate) fn build_runtime_template_context(
    runtime_addresses: &DirectRuntimeAddressPlan,
    runtime_state: &DirectRuntimeState,
) -> Result<RuntimeTemplateContext> {
    let mut context = RuntimeTemplateContext::default();

    for (scope, entries) in &runtime_addresses.slots_by_scope {
        let mut urls = BTreeMap::new();
        for (name, source) in entries {
            let url = runtime_url_for_source(source, runtime_state)?;
            urls.insert(
                name.clone(),
                serde_json::to_string(&RuntimeSlotObject { url: url.clone() }).map_err(|err| {
                    miette::miette!(
                        "failed to serialize direct runtime slot object for scope {} slot {}: \
                         {err}",
                        scope,
                        name
                    )
                })?,
            );
            urls.insert(format!("{name}.url"), url);
        }
        if !urls.is_empty() {
            context.slots_by_scope.insert(*scope as u64, urls);
        }
    }

    for (scope, entries) in &runtime_addresses.slot_items_by_scope {
        let mut urls = BTreeMap::new();
        for (name, sources) in entries {
            let mut items = Vec::with_capacity(sources.len());
            for source in sources {
                items.push(RuntimeSlotObject {
                    url: runtime_url_for_source(source, runtime_state)?,
                });
            }
            urls.insert(name.clone(), items);
        }
        if !urls.is_empty() {
            context.slot_items_by_scope.insert(*scope as u64, urls);
        }
    }

    Ok(context)
}

pub(crate) fn runtime_url_for_source(
    source: &DirectRuntimeUrlSource,
    runtime_state: &DirectRuntimeState,
) -> Result<String> {
    match source {
        DirectRuntimeUrlSource::Slot {
            component_id,
            slot,
            scheme,
        } => {
            let port = runtime_state
                .slot_ports_by_component
                .get(component_id)
                .and_then(|slots| slots.get(slot.as_str()))
                .copied()
                .ok_or_else(|| {
                    miette::miette!(
                        "missing runtime slot port for component {} slot {}",
                        component_id,
                        slot
                    )
                })?;
            Ok(format!("{scheme}://127.0.0.1:{port}"))
        }
        DirectRuntimeUrlSource::SlotItem {
            component_id,
            slot,
            item_index,
            scheme,
        } => {
            let port = runtime_state
                .slot_route_ports_by_component
                .get(component_id)
                .and_then(|slots| slots.get(slot.as_str()))
                .and_then(|ports| ports.get(*item_index))
                .copied()
                .ok_or_else(|| {
                    miette::miette!(
                        "missing runtime slot item {} for component {} slot {}",
                        item_index,
                        component_id,
                        slot
                    )
                })?;
            Ok(format!("{scheme}://127.0.0.1:{port}"))
        }
    }
}

pub(crate) fn append_runtime_config_env(
    env_map: &mut BTreeMap<String, String>,
    payload: &DirectRuntimeConfigPayload,
) -> Result<()> {
    env_map.insert(
        "AMBER_ROOT_CONFIG_SCHEMA_B64".to_string(),
        payload.root_schema_b64.clone(),
    );
    env_map.insert(
        "AMBER_COMPONENT_CONFIG_SCHEMA_B64".to_string(),
        payload.component_schema_b64.clone(),
    );
    env_map.insert(
        "AMBER_COMPONENT_CONFIG_TEMPLATE_B64".to_string(),
        payload.component_cfg_template_b64.clone(),
    );
    for path in &payload.allowed_root_leaf_paths {
        let env_var = amber_config::env_var_for_path(path)
            .map_err(|err| miette::miette!("failed to map config path {}: {err}", path))?;
        if let Ok(value) = env::var(&env_var) {
            env_map.insert(env_var, value);
        }
    }
    Ok(())
}

pub(crate) fn split_entrypoint(entrypoint: &[String]) -> Result<(String, Vec<String>)> {
    let Some(program) = entrypoint.first() else {
        return Err(miette::miette!("program entrypoint must not be empty"));
    };
    Ok((program.clone(), entrypoint[1..].to_vec()))
}

#[cfg(target_os = "linux")]
pub(crate) fn component_source_dir(component: &DirectComponentPlan) -> Result<Option<PathBuf>> {
    let Some(raw) = component.source_dir.as_deref() else {
        return Ok(None);
    };
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err(miette::miette!(
            "direct plan has non-absolute source directory {} for component {}",
            path.display(),
            component.moniker
        ));
    }
    Ok(Some(path))
}

#[cfg(target_os = "linux")]
pub(crate) fn component_program_read_only_mounts(
    component: &DirectComponentPlan,
    source_dir: Option<&Path>,
) -> Result<Vec<ReadOnlyMount>> {
    let mut mounts = BTreeMap::<PathBuf, ReadOnlyMount>::new();
    if let Some(source_dir) = source_dir
        && source_dir.is_absolute()
    {
        mounts.insert(
            source_dir.to_path_buf(),
            ReadOnlyMount {
                source: source_dir.to_path_buf(),
                dest: source_dir.to_path_buf(),
            },
        );
    }

    let Some(program_path) = component_execution_program_path(component)? else {
        return Ok(mounts.into_values().collect());
    };
    let program_path =
        ensure_absolute_direct_program_path(&program_path, component.moniker.as_str())?;
    let program_path = Path::new(&program_path);
    if let Some(parent) = program_path.parent() {
        mounts.entry(parent.to_path_buf()).or_insert(ReadOnlyMount {
            source: parent.to_path_buf(),
            dest: parent.to_path_buf(),
        });
    }

    Ok(mounts.into_values().collect())
}

#[cfg(target_os = "linux")]
pub(crate) fn component_execution_program_path(
    component: &DirectComponentPlan,
) -> Result<Option<String>> {
    match &component.program.execution {
        DirectProgramExecutionPlan::Direct { entrypoint, .. } => Ok(entrypoint.first().cloned()),
        DirectProgramExecutionPlan::HelperRunner {
            entrypoint_b64,
            template_spec_b64,
            ..
        } => {
            if let Some(raw) = entrypoint_b64.as_ref() {
                return decode_entrypoint_payload_program(raw).map(Some);
            }
            if let Some(raw) = template_spec_b64.as_ref() {
                return decode_template_spec_program(raw).map(Some);
            }
            Ok(None)
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn decode_entrypoint_payload_program(raw_b64: &str) -> Result<String> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw_b64.as_bytes())
        .map_err(|err| miette::miette!("invalid entrypoint payload: {err}"))?;
    let entrypoint: Vec<String> = serde_json::from_slice(&decoded)
        .map_err(|err| miette::miette!("invalid entrypoint payload: {err}"))?;
    entrypoint
        .into_iter()
        .next()
        .ok_or_else(|| miette::miette!("entrypoint payload is empty"))
}

#[cfg(target_os = "linux")]
pub(crate) fn decode_template_spec_program(raw_b64: &str) -> Result<String> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw_b64.as_bytes())
        .map_err(|err| miette::miette!("invalid template spec payload: {err}"))?;
    let spec: TemplateSpec = serde_json::from_slice(&decoded)
        .map_err(|err| miette::miette!("invalid template spec payload: {err}"))?;
    let path_template = spec
        .program
        .entrypoint
        .first()
        .ok_or_else(|| miette::miette!("template spec program entrypoint is empty"))?;
    render_program_arg_template_literal(path_template)
}

#[cfg(target_os = "linux")]
pub(crate) fn render_program_arg_template_literal(arg: &ProgramArgTemplate) -> Result<String> {
    let ProgramArgTemplate::Arg(parts) = arg else {
        return Err(miette::miette!(
            "internal error: template spec program entrypoint starts with a conditional arg item"
        ));
    };
    render_template_string_literal(parts)
}

#[cfg(target_os = "linux")]
pub(crate) fn render_template_string_literal(parts: &[TemplatePart]) -> Result<String> {
    let mut out = String::new();
    for part in parts {
        match part {
            TemplatePart::Lit { lit } => out.push_str(lit),
            TemplatePart::Config { config } => {
                return Err(miette::miette!(
                    "internal error: unresolved runtime config interpolation `{config}` in direct \
                     program path"
                ));
            }
            TemplatePart::Slot { slot, .. } => {
                return Err(miette::miette!(
                    "internal error: unresolved slot interpolation `{slot}` in direct program path"
                ));
            }
            TemplatePart::Item { item, .. } => {
                return Err(miette::miette!(
                    "internal error: unresolved repeated item interpolation `{item}` in direct \
                     program path"
                ));
            }
            TemplatePart::CurrentItem { item } => {
                return Err(miette::miette!(
                    "internal error: unresolved repeated item interpolation `{item}` in direct \
                     program path"
                ));
            }
        }
    }
    if out.is_empty() {
        return Err(miette::miette!(
            "internal error: template spec program entrypoint is empty"
        ));
    }
    Ok(out)
}

pub(crate) fn ensure_absolute_direct_program_path(
    program: &str,
    component_moniker: &str,
) -> Result<String> {
    if Path::new(program).is_absolute() {
        return Ok(program.to_string());
    }

    Err(miette::miette!(
        "direct plan for component {} contains non-absolute program path `{}`; re-run `amber \
         compile --direct` with a build that resolves direct executable paths at compile time",
        component_moniker,
        program
    ))
}

pub(crate) fn decode_mount_parent_dirs(
    raw_b64: &str,
    runtime_config: Option<&DirectRuntimeConfigPayload>,
    runtime_template_context: &RuntimeTemplateContext,
    env_map: &BTreeMap<String, String>,
) -> Result<Vec<PathBuf>> {
    decode_mount_parent_dirs_with_env(raw_b64, runtime_config, runtime_template_context, env_map)
}

pub(crate) fn decode_mount_parent_dirs_with_env(
    raw_b64: &str,
    runtime_config: Option<&DirectRuntimeConfigPayload>,
    runtime_template_context: &RuntimeTemplateContext,
    env_map: &BTreeMap<String, String>,
) -> Result<Vec<PathBuf>> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw_b64.as_bytes())
        .map_err(|err| miette::miette!("invalid AMBER_MOUNT_SPEC_B64: {err}"))?;
    let mounts: Vec<MountSpec> = serde_json::from_slice(&decoded)
        .map_err(|err| miette::miette!("invalid mount spec payload: {err}"))?;
    let mut parents = BTreeSet::new();
    for path in rendered_mount_paths(&mounts, runtime_config, runtime_template_context, env_map)? {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err(miette::miette!(
                "invalid mount path {}: expected absolute path",
                path.display()
            ));
        }
        let parent = path.parent().ok_or_else(|| {
            miette::miette!(
                "invalid mount path {}: missing parent directory",
                path.display()
            )
        })?;
        parents.insert(parent.to_path_buf());
    }
    Ok(parents.into_iter().collect())
}

pub(crate) fn rendered_mount_paths(
    mounts: &[MountSpec],
    runtime_config: Option<&DirectRuntimeConfigPayload>,
    runtime_template_context: &RuntimeTemplateContext,
    env_map: &BTreeMap<String, String>,
) -> Result<Vec<String>> {
    if mounts
        .iter()
        .all(|mount| matches!(mount, MountSpec::Literal { .. }))
    {
        return Ok(mounts
            .iter()
            .map(|mount| match mount {
                MountSpec::Literal { path, .. } => path.clone(),
                MountSpec::Template(_) => unreachable!("checked above"),
            })
            .collect());
    }

    let runtime_config = runtime_config.ok_or_else(|| {
        miette::miette!("mount specs require runtime config to resolve mount paths")
    })?;
    let (component_config, component_schema) =
        resolve_runtime_component_config(runtime_config, runtime_template_context, env_map)?;
    config::render_mount_specs(
        mounts,
        Some(&component_config),
        Some(&component_schema),
        runtime_template_context,
    )
    .map(|rendered| rendered.into_iter().map(|(path, _)| path).collect())
    .map_err(|err| miette::miette!(err.to_string()))
}

pub(crate) fn resolve_runtime_component_config(
    runtime_config: &DirectRuntimeConfigPayload,
    runtime_template_context: &RuntimeTemplateContext,
    env_map: &BTreeMap<String, String>,
) -> Result<(serde_json::Value, serde_json::Value)> {
    let root_schema = decode_runtime_json_b64(
        "runtime root config schema",
        runtime_config.root_schema_b64.as_str(),
    )?;
    let component_schema = decode_runtime_json_b64(
        "runtime component config schema",
        runtime_config.component_schema_b64.as_str(),
    )?;
    let component_template = ConfigTemplatePayload::from_value(decode_runtime_json_b64(
        "runtime component config template",
        runtime_config.component_cfg_template_b64.as_str(),
    )?)
    .map_err(|err| miette::miette!("invalid runtime component config template: {err}"))?;
    let config_env = collect_runtime_config_env(env_map);
    let component_config = config::resolve_runtime_component_config(
        &root_schema,
        &component_schema,
        &component_template,
        &config_env,
        runtime_template_context,
    )
    .map_err(|err| {
        miette::miette!("failed to resolve runtime component config for mount paths: {err}")
    })?;

    Ok((component_config, component_schema))
}

pub(crate) fn collect_runtime_config_env(
    env_map: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut config_env = BTreeMap::new();
    for (key, value) in env_map {
        if !key.starts_with(CONFIG_ENV_PREFIX) {
            continue;
        }
        config_env.insert(key.clone(), value.clone());
    }
    config_env
}

pub(crate) fn decode_runtime_json_b64(name: &str, raw_b64: &str) -> Result<serde_json::Value> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw_b64.as_bytes())
        .map_err(|err| miette::miette!("invalid {name}: {err}"))?;
    serde_json::from_slice(&decoded).map_err(|err| miette::miette!("invalid {name}: {err}"))
}

pub(crate) async fn spawn_managed_process(
    spec: ProcessSpec,
    sandbox: &mut DirectSandbox,
    children: &mut Vec<ManagedChild>,
    log_tasks: &mut Vec<tokio::task::JoinHandle<()>>,
) -> Result<u32> {
    let (program, args) = match spec.sandbox {
        ProcessSandbox::Sandboxed => sandbox.wrap_command(&spec)?,
        ProcessSandbox::Unsandboxed => {
            #[cfg(target_os = "linux")]
            if !matches!(spec.network, ProcessNetwork::Host) {
                return Err(miette::miette!(
                    "unsandboxed direct processes must use host networking"
                ));
            }
            (spec.program.clone(), spec.args.clone())
        }
    };
    #[cfg(target_os = "linux")]
    let mut args = args;
    #[cfg(target_os = "linux")]
    let namespace_join = if matches!(spec.sandbox, ProcessSandbox::Sandboxed)
        && matches!(sandbox, DirectSandbox::Bubblewrap { .. })
    {
        match spec.network {
            ProcessNetwork::Join(pid) => prepare_linux_namespace_join(pid)?,
            _ => None,
        }
    } else {
        None
    };
    #[cfg(target_os = "linux")]
    let pid_capture = if matches!(spec.sandbox, ProcessSandbox::Sandboxed)
        && matches!(sandbox, DirectSandbox::Bubblewrap { .. })
    {
        insert_bubblewrap_info_fd(&mut args, 3)?;
        SpawnPidCapture::BubblewrapChild
    } else {
        SpawnPidCapture::WrapperProcess
    };
    let mut command = TokioCommand::new(program);
    command.args(args);
    command.current_dir(&spec.work_dir);
    configure_managed_command_env(&mut command, &spec.work_dir, &spec.env);
    spawn_managed_command(
        spec.name,
        command,
        #[cfg(target_os = "linux")]
        namespace_join,
        #[cfg(target_os = "linux")]
        pid_capture,
        children,
        log_tasks,
    )
    .await
}
