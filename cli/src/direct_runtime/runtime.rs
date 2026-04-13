use super::*;

pub(crate) struct ManagedChild {
    pub(crate) name: String,
    pub(crate) wrapper: Option<tokio::process::Child>,
    #[cfg(target_os = "linux")]
    pub(crate) wrapper_pid: u32,
    #[cfg(target_os = "linux")]
    pub(crate) managed_pid: u32,
}

#[derive(Debug)]
pub(crate) struct ProcessSpec {
    pub(crate) name: String,
    pub(crate) program: String,
    pub(crate) args: Vec<String>,
    pub(crate) env: BTreeMap<String, String>,
    pub(crate) work_dir: PathBuf,
    pub(crate) sandbox: ProcessSandbox,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) drop_all_caps: bool,
    #[cfg(target_os = "linux")]
    pub(crate) read_only_mounts: Vec<ReadOnlyMount>,
    pub(crate) writable_dirs: Vec<PathBuf>,
    pub(crate) bind_dirs: Vec<PathBuf>,
    pub(crate) bind_mounts: Vec<BindMount>,
    pub(crate) hidden_paths: Vec<PathBuf>,
    pub(crate) network: ProcessNetwork,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReadOnlyMount {
    pub(crate) source: PathBuf,
    pub(crate) dest: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BindMount {
    pub(crate) source: PathBuf,
    pub(crate) dest: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessNetwork {
    Host,
    #[cfg(target_os = "linux")]
    Isolated,
    #[cfg(target_os = "linux")]
    Join(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessSandbox {
    Sandboxed,
    Unsandboxed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct DirectMountPreview {
    pub(crate) source: String,
    pub(crate) dest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct DirectDockerMountProxyPreview {
    pub(crate) path: String,
    pub(crate) tcp_host: String,
    pub(crate) tcp_port: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct DirectResolvedProcessPreview {
    pub(crate) argv: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) env: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) docker_mount_proxies: Vec<DirectDockerMountProxyPreview>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct DirectLaunchProcessPreview {
    pub(crate) role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) component: Option<String>,
    pub(crate) name: String,
    pub(crate) argv: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) env: BTreeMap<String, String>,
    pub(crate) current_dir: String,
    pub(crate) sandbox: String,
    pub(crate) network: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) writable_dirs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) bind_dirs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) bind_mounts: Vec<DirectMountPreview>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) hidden_paths: Vec<String>,
    #[cfg(target_os = "linux")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) read_only_mounts: Vec<DirectMountPreview>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) resolved_process: Option<DirectResolvedProcessPreview>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct DirectSiteLaunchPreview {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) router_public_key_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) processes: Vec<DirectLaunchProcessPreview>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) inspectability_warnings: Vec<String>,
}

#[derive(Debug)]
pub(crate) enum RuntimeExitReason {
    CtrlC,
    ChildExited {
        name: String,
        status: std::process::ExitStatus,
    },
}

pub(crate) const DIRECT_SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(5);
pub(crate) const DIRECT_CHILD_POLL_INTERVAL: Duration = Duration::from_millis(150);
pub(crate) const DIRECT_LOCAL_TARGET_READY_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const DIRECT_MESH_ENDPOINT_READY_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DirectControlSocketPaths {
    pub(crate) artifact_link: PathBuf,
    pub(crate) current_link: PathBuf,
    pub(crate) runtime: PathBuf,
}

pub(crate) struct DirectRuntimeInputs {
    pub(crate) plan_root: PathBuf,
    pub(crate) direct_plan: DirectPlan,
    pub(crate) mesh_plan: MeshProvisionPlan,
}

pub(crate) async fn run_direct_init(args: RunDirectInitArgs) -> Result<()> {
    let plan_path = canonicalize_user_path(&args.plan, "direct plan")?;
    let DirectRuntimeInputs {
        plan_root,
        direct_plan,
        mesh_plan,
    } = load_direct_runtime_inputs(&plan_path)?;
    let storage_root = direct_storage_root(&plan_root, args.storage_root.as_deref())
        .into_diagnostic()
        .wrap_err("failed to resolve direct storage root")?;

    let runtime_dir = if let Some(runtime_root) = args.runtime_root.as_ref() {
        fs::create_dir_all(runtime_root)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "failed to create direct runtime workspace {}",
                    runtime_root.display()
                )
            })?;
        None
    } else {
        Some(
            tempfile::Builder::new()
                .prefix("amber-direct-")
                .tempdir()
                .into_diagnostic()
                .wrap_err("failed to create direct runtime workspace")?,
        )
    };
    let runtime_root = runtime_dir
        .as_ref()
        .map(|dir| dir.path().to_path_buf())
        .or_else(|| args.runtime_root.clone())
        .expect("runtime root should be available");
    let runtime_state_path = direct_runtime_state_path(&plan_root);
    let mut children = Vec::<ManagedChild>::new();
    let mut log_tasks = Vec::new();
    let mut component_sidecar_pid_by_id = HashMap::new();
    let mut control_socket_paths = None;
    let existing_peer_ports_by_id = read_existing_peer_ports(
        args.existing_peer_ports.as_deref(),
        "direct existing peer ports",
    )?;
    let discovered_peer_identities_by_id = read_existing_peer_identities(
        args.existing_peer_identities.as_deref(),
        "direct existing peer identities",
    )?;
    let existing_peer_identities_by_id =
        merge_existing_mesh_peer_identities(&mesh_plan, &discovered_peer_identities_by_id)?;

    let supervision = async {
        let mut sandbox = DirectSandbox::detect(&runtime_root);
        if !sandbox.is_available() {
            return Err(miette::miette!(
                "direct runtime requires a sandbox backend for process isolation; {}",
                missing_direct_sandbox_help()
            ));
        }
        #[cfg(target_os = "linux")]
        let slirp4netns = find_in_path("slirp4netns").ok_or_else(|| {
            miette::miette!(
                "direct runtime requires `slirp4netns` on Linux for isolated component networking"
            )
        })?;
        let runtime_state = if args.skip_router || !existing_peer_ports_by_id.is_empty() {
            materialize_direct_runtime_with_existing(
                &plan_root,
                &runtime_root,
                &direct_plan,
                &mesh_plan,
                args.router_mesh_port,
                DirectExistingMeshState {
                    reuse_existing: args.runtime_root.is_some() && runtime_state_path.is_file(),
                    peer_ports_by_id: &existing_peer_ports_by_id,
                    peer_identities_by_id: &existing_peer_identities_by_id,
                },
            )?
        } else {
            materialize_direct_runtime(
                &plan_root,
                &runtime_root,
                &direct_plan,
                &mesh_plan,
                args.router_mesh_port,
                args.runtime_root.is_some() && runtime_state_path.is_file(),
            )?
        };
        project_existing_direct_peer_identities(
            &runtime_root,
            &direct_plan,
            &existing_peer_identities_by_id,
        )?;
        #[cfg(target_os = "linux")]
        let mesh_network =
            configure_direct_mesh_network(&runtime_root, &runtime_state, &direct_plan)?;
        #[cfg(not(target_os = "linux"))]
        configure_direct_mesh_network(&runtime_root, &runtime_state, &direct_plan)?;

        let router_binary = resolve_runtime_binary("amber-router")?;
        if !args.skip_router
            && let Some(router) = direct_plan.router.as_ref()
        {
            let paths = DirectControlSocketPaths {
                artifact_link: resolve_direct_artifact_path(
                    &plan_root,
                    &router.control_socket_path,
                ),
                current_link: direct_current_control_socket_path(&plan_root),
                runtime: direct_runtime_control_socket_path(&runtime_root),
            };
            let direct_control_artifact_link_dir = paths
                .artifact_link
                .parent()
                .ok_or_else(|| miette::miette!("invalid direct control socket path"))?
                .to_path_buf();
            let direct_control_current_link_dir = paths
                .current_link
                .parent()
                .ok_or_else(|| miette::miette!("invalid current control socket path"))?
                .to_path_buf();
            let direct_control_runtime_dir = paths
                .runtime
                .parent()
                .ok_or_else(|| miette::miette!("invalid runtime control socket path"))?
                .to_path_buf();
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
            fs::create_dir_all(&work_dir)
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!(
                        "failed to create router runtime directory {}",
                        work_dir.display()
                    )
                })?;
            fs::create_dir_all(&direct_control_artifact_link_dir)
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!(
                        "failed to create router control directory {}",
                        direct_control_artifact_link_dir.display()
                    )
                })?;
            fs::create_dir_all(&direct_control_current_link_dir)
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!(
                        "failed to create current router control directory {}",
                        direct_control_current_link_dir.display()
                    )
                })?;
            fs::create_dir_all(&direct_control_runtime_dir)
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!(
                        "failed to create runtime router control directory {}",
                        direct_control_runtime_dir.display()
                    )
                })?;
            if paths.runtime.exists() {
                fs::remove_file(&paths.runtime)
                    .into_diagnostic()
                    .wrap_err_with(|| {
                        format!(
                            "failed to remove stale runtime router control socket {}",
                            paths.runtime.display()
                        )
                    })?;
            }
            ensure_direct_control_socket_link(
                &paths.artifact_link,
                &paths.current_link,
                "router control symlink",
            )?;
            ensure_direct_control_socket_link(
                &paths.current_link,
                &paths.runtime,
                "runtime router control symlink",
            )?;
            let spec = ProcessSpec {
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
                bind_dirs: vec![direct_control_runtime_dir.clone()],
                bind_mounts: Vec::new(),
                hidden_paths: Vec::new(),
                network: ProcessNetwork::Host,
            };
            let _ =
                spawn_managed_process(spec, &mut sandbox, &mut children, &mut log_tasks).await?;
            control_socket_paths = Some(paths);
        }

        let mut components_by_id = HashMap::new();
        for component in &direct_plan.components {
            components_by_id.insert(component.id, component);
        }

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
                    let value = rewrite_sidecar_env_passthrough_for_slirp(
                        passthrough.as_str(),
                        value.as_str(),
                    );
                    env.insert(passthrough.clone(), value);
                }
            }
            let work_dir = runtime_root.join(&component.program.work_dir);
            fs::create_dir_all(&work_dir)
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!(
                        "failed to create component runtime directory {}",
                        work_dir.display()
                    )
                })?;
            let control_socket_path = direct_component_control_socket_path(&work_dir, component.id);
            let control_socket_dir = control_socket_path
                .parent()
                .ok_or_else(|| miette::miette!("invalid sidecar control socket path"))?
                .to_path_buf();
            fs::create_dir_all(&control_socket_dir)
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!(
                        "failed to create sidecar control directory {}",
                        control_socket_dir.display()
                    )
                })?;
            if control_socket_path.exists() {
                fs::remove_file(&control_socket_path)
                    .into_diagnostic()
                    .wrap_err_with(|| {
                        format!(
                            "failed to remove stale sidecar control socket {}",
                            control_socket_path.display()
                        )
                    })?;
            }
            env.insert(
                "AMBER_ROUTER_CONTROL_SOCKET_PATH".to_string(),
                control_socket_path.display().to_string(),
            );
            let spec = ProcessSpec {
                name: component.sidecar.log_name.clone(),
                program: router_binary.clone(),
                args: Vec::new(),
                env,
                work_dir,
                sandbox: ProcessSandbox::Sandboxed,
                drop_all_caps: true,
                #[cfg(target_os = "linux")]
                read_only_mounts: vec![ReadOnlyMount {
                    source: runtime_root.join("mesh"),
                    dest: runtime_root.join("mesh"),
                }],
                writable_dirs: Vec::new(),
                bind_dirs: vec![control_socket_dir],
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
            };
            let sidecar_pid =
                spawn_managed_process(spec, &mut sandbox, &mut children, &mut log_tasks).await?;
            #[cfg(target_os = "linux")]
            {
                let mesh_port = mesh_network
                    .component_mesh_port_by_id
                    .get(&component.id)
                    .copied()
                    .ok_or_else(|| {
                        miette::miette!(
                            "missing sidecar mesh listen port for component {}",
                            component.moniker
                        )
                    })?;
                spawn_component_slirp4netns(
                    &slirp4netns,
                    &runtime_root,
                    component,
                    sidecar_pid,
                    mesh_port,
                    &mut children,
                    &mut log_tasks,
                )
                .await?;
            }
            component_sidecar_pid_by_id.insert(component.id, sidecar_pid);
        }

        for component_id in &direct_plan.startup_order {
            let component = components_by_id.get(component_id).ok_or_else(|| {
                miette::miette!(
                    "direct plan startup order references unknown component id {}",
                    component_id
                )
            })?;
            let mut spec = component_program_spec(
                &runtime_root,
                &storage_root,
                component,
                &direct_plan.runtime_addresses,
                &runtime_state,
            )?;
            spec.hidden_paths.push(runtime_root.join("mesh"));
            #[cfg(target_os = "linux")]
            {
                let pid = component_sidecar_pid_by_id
                    .get(component_id)
                    .copied()
                    .ok_or_else(|| {
                        miette::miette!("missing sidecar pid for component {}", component.moniker)
                    })?;
                spec.network = ProcessNetwork::Join(pid);
            }
            let _ =
                spawn_managed_process(spec, &mut sandbox, &mut children, &mut log_tasks).await?;
            #[cfg(target_os = "linux")]
            wait_for_component_local_targets(
                component,
                &runtime_root,
                component_sidecar_pid_by_id.get(component_id).copied(),
                DIRECT_LOCAL_TARGET_READY_TIMEOUT,
            )
            .await?;
            #[cfg(not(target_os = "linux"))]
            wait_for_component_local_targets(
                component,
                &runtime_root,
                None,
                DIRECT_LOCAL_TARGET_READY_TIMEOUT,
            )
            .await?;
        }

        wait_for_direct_mesh_endpoints(&runtime_state, DIRECT_MESH_ENDPOINT_READY_TIMEOUT).await?;
        write_direct_runtime_state(&plan_root, &runtime_state)?;
        supervise_children(&mut children).await
    }
    .await;
    cleanup_direct_runtime(
        &mut children,
        log_tasks,
        &runtime_state_path,
        control_socket_paths.as_ref(),
        runtime_dir,
    )
    .await;

    let (reason, exit_code) = supervision?;
    match reason {
        RuntimeExitReason::CtrlC => Ok(()),
        RuntimeExitReason::ChildExited { name, status } => {
            if status.success() {
                Ok(())
            } else {
                eprintln!(
                    "direct runtime stopped because {} exited (status: {}, exit code: {})",
                    name, status, exit_code
                );
                std::process::exit(exit_code);
            }
        }
    }
}

fn read_existing_peer_ports(
    path: Option<&Path>,
    description: &str,
) -> Result<BTreeMap<String, u16>> {
    let Some(path) = path else {
        return Ok(BTreeMap::new());
    };
    let raw = fs::read_to_string(path)
        .map_err(|err| miette::miette!("failed to read {description} {}: {err}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|err| miette::miette!("invalid {description} {}: {err}", path.display()))
}

pub(crate) fn read_existing_peer_identities(
    path: Option<&Path>,
    description: &str,
) -> Result<BTreeMap<String, MeshIdentityPublic>> {
    let Some(path) = path else {
        return Ok(BTreeMap::new());
    };
    let raw = fs::read_to_string(path)
        .map_err(|err| miette::miette!("failed to read {description} {}: {err}", path.display()))?;
    let identities: BTreeMap<String, MeshIdentityPublic> = serde_json::from_str(&raw)
        .map_err(|err| miette::miette!("invalid {description} {}: {err}", path.display()))?;
    for (peer_id, identity) in &identities {
        if identity.id != *peer_id {
            return Err(miette::miette!(
                "{description} entry `{peer_id}` does not match embedded identity id `{}`",
                identity.id
            ));
        }
    }
    Ok(identities)
}

fn merge_existing_mesh_peer_identities(
    mesh_plan: &MeshProvisionPlan,
    discovered_peer_identities_by_id: &BTreeMap<String, MeshIdentityPublic>,
) -> Result<BTreeMap<String, MeshIdentityPublic>> {
    let mut merged = mesh_plan
        .existing_peer_identities
        .iter()
        .cloned()
        .map(|identity| (identity.id.clone(), identity))
        .collect::<BTreeMap<_, _>>();

    for (peer_id, discovered_identity) in discovered_peer_identities_by_id {
        if let Some(embedded_identity) = merged.get(peer_id) {
            if embedded_identity.id != discovered_identity.id
                || embedded_identity.public_key != discovered_identity.public_key
                || embedded_identity.mesh_scope != discovered_identity.mesh_scope
            {
                return Err(miette::miette!(
                    "existing peer identity `{peer_id}` from the direct runtime arguments does \
                     not match the embedded mesh provision plan"
                ));
            }
            continue;
        }
        merged.insert(peer_id.clone(), discovered_identity.clone());
    }

    Ok(merged)
}

pub(crate) fn project_existing_direct_peer_identities(
    runtime_root: &Path,
    direct_plan: &DirectPlan,
    existing_peer_identities_by_id: &BTreeMap<String, MeshIdentityPublic>,
) -> Result<()> {
    if existing_peer_identities_by_id.is_empty() {
        return Ok(());
    }
    for component in &direct_plan.components {
        project_existing_peer_identities_into_mesh_config(
            &runtime_root.join(&component.sidecar.mesh_config_path),
            existing_peer_identities_by_id,
        )?;
    }
    if let Some(router) = direct_plan.router.as_ref() {
        project_existing_peer_identities_into_mesh_config(
            &runtime_root.join(&router.mesh_config_path),
            existing_peer_identities_by_id,
        )?;
    } else {
        project_existing_peer_identities_into_mesh_config(
            &runtime_root.join("mesh/router").join(MESH_CONFIG_FILENAME),
            existing_peer_identities_by_id,
        )?;
    }
    Ok(())
}

pub(crate) fn project_existing_peer_identities_into_mesh_config(
    path: &Path,
    existing_peer_identities_by_id: &BTreeMap<String, MeshIdentityPublic>,
) -> Result<()> {
    if existing_peer_identities_by_id.is_empty() || !path.is_file() {
        return Ok(());
    }

    let mut config = read_mesh_config_public(path)?;
    let canonical_mesh_scope = existing_peer_identities_by_id
        .values()
        .find_map(|identity| identity.mesh_scope.clone());
    let mut changed = false;

    if let Some(identity) = existing_peer_identities_by_id.get(&config.identity.id) {
        if config.identity.public_key != identity.public_key
            || config.identity.mesh_scope != identity.mesh_scope
        {
            config.identity.public_key = identity.public_key;
            config.identity.mesh_scope = identity.mesh_scope.clone();
            changed = true;
        }
    } else if let Some(mesh_scope) = canonical_mesh_scope.as_ref()
        && config.identity.mesh_scope.as_deref() != Some(mesh_scope.as_str())
    {
        config.identity.mesh_scope = Some(mesh_scope.clone());
        changed = true;
    }

    for peer in &mut config.peers {
        let Some(identity) = existing_peer_identities_by_id.get(&peer.id) else {
            continue;
        };
        if peer.public_key == identity.public_key {
            continue;
        }
        peer.public_key = identity.public_key;
        changed = true;
    }

    if changed {
        write_mesh_config_public(path, &config)?;
    }
    Ok(())
}

pub(crate) fn resolve_direct_artifact_path(plan_root: &Path, path: &str) -> PathBuf {
    let path = Path::new(path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        plan_root.join(path)
    }
}

pub(crate) fn direct_storage_root(
    plan_root: &Path,
    override_root: Option<&Path>,
) -> std::io::Result<PathBuf> {
    if let Some(override_root) = override_root {
        return Ok(if override_root.is_absolute() {
            override_root.to_path_buf()
        } else {
            std::env::current_dir()?.join(override_root)
        });
    }

    let name = plan_root
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("amber-direct");
    let parent = plan_root.parent().unwrap_or_else(|| Path::new("."));
    Ok(parent.join(format!(".{name}.amber-state")))
}

pub(crate) fn direct_current_control_socket_path(plan_root: &Path) -> PathBuf {
    amber_mesh::stable_temp_socket_path("amber-direct-control", "current", plan_root)
}

pub(crate) fn direct_runtime_control_socket_path(runtime_root: &Path) -> PathBuf {
    amber_mesh::stable_temp_socket_path("amber-direct-control", "runtime", runtime_root)
}

fn direct_component_control_socket_path(work_dir: &Path, component_id: usize) -> PathBuf {
    amber_mesh::stable_temp_socket_path(
        "amber-direct-control",
        &format!("sidecar-{component_id}"),
        work_dir,
    )
}

#[cfg(unix)]
pub(crate) fn ensure_direct_control_socket_link(
    link: &Path,
    target: &Path,
    description: &str,
) -> Result<()> {
    if fs::read_link(link)
        .ok()
        .is_some_and(|existing_target| existing_target == target)
    {
        return Ok(());
    }

    if fs::symlink_metadata(link).is_ok() {
        fs::remove_file(link)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to remove stale {description} {}", link.display()))?;
    }

    std::os::unix::fs::symlink(target, link)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create {description} {} -> {}",
                link.display(),
                target.display()
            )
        })
}

#[cfg(not(unix))]
pub(crate) fn ensure_direct_control_socket_link(
    link: &Path,
    target: &Path,
    description: &str,
) -> Result<()> {
    let _ = (link, target, description);
    Err(miette::miette!(
        "direct runtime control sockets require unix symlink support"
    ))
}

pub(crate) fn remove_direct_control_socket_link(paths: &DirectControlSocketPaths) {
    #[cfg(unix)]
    {
        if fs::read_link(&paths.current_link)
            .ok()
            .is_some_and(|target| target == paths.runtime)
        {
            let _ = fs::remove_file(&paths.current_link);
        }
    }

    #[cfg(not(unix))]
    {
        let _ = fs::remove_file(&paths.current_link);
    }
}

pub(crate) async fn cleanup_direct_runtime(
    children: &mut [ManagedChild],
    log_tasks: Vec<tokio::task::JoinHandle<()>>,
    runtime_state_path: &Path,
    control_socket_paths: Option<&DirectControlSocketPaths>,
    runtime_dir: Option<tempfile::TempDir>,
) {
    terminate_children(children).await;
    for task in log_tasks {
        let _ = task.await;
    }
    if let Some(paths) = control_socket_paths {
        remove_direct_control_socket_link(paths);
        let _ = fs::remove_file(&paths.runtime);
    }
    let _ = fs::remove_file(runtime_state_path);
    drop(runtime_dir);
}

pub(crate) fn direct_runtime_state_path(plan_root: &Path) -> PathBuf {
    plan_root.join(".amber").join("direct-runtime.json")
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct DirectRuntimeState {
    #[serde(default)]
    pub(crate) slot_ports_by_component: BTreeMap<usize, BTreeMap<String, u16>>,
    #[serde(default)]
    pub(crate) slot_route_ports_by_component: BTreeMap<usize, BTreeMap<String, Vec<u16>>>,
    #[serde(default)]
    pub(crate) dynamic_caps_port_by_component: BTreeMap<usize, u16>,
    #[serde(default)]
    pub(crate) component_mesh_port_by_id: BTreeMap<usize, u16>,
    #[serde(default)]
    pub(crate) router_mesh_port: Option<u16>,
}

#[derive(Debug, Default)]
pub(crate) struct DirectMeshNetworkPlan {
    #[cfg(target_os = "linux")]
    component_mesh_port_by_id: HashMap<usize, u16>,
}

pub(crate) fn assign_direct_runtime_ports(
    runtime_root: &Path,
    direct_plan: &DirectPlan,
    fixed_router_mesh_port: Option<u16>,
) -> Result<DirectRuntimeState> {
    assign_direct_runtime_ports_with_existing(
        runtime_root,
        direct_plan,
        fixed_router_mesh_port,
        &BTreeMap::new(),
    )
}

pub(crate) fn assign_direct_runtime_ports_with_existing(
    runtime_root: &Path,
    direct_plan: &DirectPlan,
    fixed_router_mesh_port: Option<u16>,
    existing_peer_ports_by_id: &BTreeMap<String, u16>,
) -> Result<DirectRuntimeState> {
    let mut state = DirectRuntimeState::default();
    let mut reserved = BTreeSet::new();
    let mut mesh_port_by_peer_id = HashMap::<String, u16>::new();
    let mut component_configs = Vec::new();

    for (peer_id, port) in existing_peer_ports_by_id {
        if !reserved.insert(*port) {
            return Err(miette::miette!(
                "runtime port {} was requested twice in one direct runtime",
                port
            ));
        }
        mesh_port_by_peer_id.insert(peer_id.clone(), *port);
    }

    for component in &direct_plan.components {
        let path = runtime_root.join(&component.sidecar.mesh_config_path);
        let mut config = read_mesh_config_public(path.as_path())?;
        let mesh_port = allocate_direct_runtime_port(&mut reserved, None)?;
        if mesh_port_by_peer_id
            .insert(config.identity.id.clone(), mesh_port)
            .is_some()
        {
            return Err(miette::miette!(
                "mesh peer id {} was registered twice in one direct runtime",
                config.identity.id
            ));
        }
        config.mesh_listen = SocketAddr::new(config.mesh_listen.ip(), mesh_port);
        if let Some(dynamic_caps_listen) = config.dynamic_caps_listen.as_mut() {
            let port = allocate_direct_runtime_port(&mut reserved, None)?;
            *dynamic_caps_listen = SocketAddr::new(dynamic_caps_listen.ip(), port);
            state
                .dynamic_caps_port_by_component
                .insert(component.id, port);
        }

        let mut slot_route_ports: BTreeMap<String, Vec<(u16, u16)>> = BTreeMap::new();
        for route in &mut config.outbound {
            let authored_port = route.listen_port;
            let port = allocate_direct_runtime_port(&mut reserved, None)?;
            route.listen_port = port;
            slot_route_ports
                .entry(route.slot.clone())
                .or_default()
                .push((authored_port, port));
        }
        for ports in slot_route_ports.values_mut() {
            // Placeholder listen ports are allocated in authored binding order during compile.
            // Preserve that order when assigning ephemeral direct-runtime ports so `${item...}`
            // continues to match the compiled item indices.
            ports.sort_unstable_by_key(|(authored_port, _)| *authored_port);
        }
        let slot_route_ports: BTreeMap<String, Vec<u16>> = slot_route_ports
            .into_iter()
            .map(|(slot, ports)| {
                (
                    slot,
                    ports
                        .into_iter()
                        .map(|(_, runtime_port)| runtime_port)
                        .collect(),
                )
            })
            .collect();

        let slot_ports = slot_route_ports
            .iter()
            .filter_map(|(slot, ports)| (ports.len() == 1).then_some((slot.clone(), ports[0])))
            .collect();

        state
            .component_mesh_port_by_id
            .insert(component.id, mesh_port);
        state
            .slot_ports_by_component
            .insert(component.id, slot_ports);
        state
            .slot_route_ports_by_component
            .insert(component.id, slot_route_ports);
        component_configs.push((path, config));
    }

    let mut router_config = if let Some(router) = direct_plan.router.as_ref() {
        let path = runtime_root.join(&router.mesh_config_path);
        let mut config = read_mesh_config_public(path.as_path())?;
        let mesh_port = allocate_direct_runtime_port(&mut reserved, fixed_router_mesh_port)?;
        if let Some(existing) = mesh_port_by_peer_id.insert(config.identity.id.clone(), mesh_port)
            && existing != mesh_port
        {
            return Err(miette::miette!(
                "mesh peer id {} was registered with conflicting ports {} and {}",
                config.identity.id,
                existing,
                mesh_port
            ));
        }
        config.mesh_listen = SocketAddr::new(
            cross_site_router_mesh_bind_ip(config.mesh_listen.ip(), fixed_router_mesh_port),
            mesh_port,
        );
        state.router_mesh_port = Some(mesh_port);
        Some((path, config))
    } else {
        None
    };

    for (_, config) in &mut component_configs {
        rewrite_direct_mesh_peer_addrs(config, &mesh_port_by_peer_id)?;
    }
    if let Some((_, config)) = router_config.as_mut() {
        rewrite_direct_mesh_peer_addrs(config, &mesh_port_by_peer_id)?;
    }

    for (path, config) in component_configs {
        write_mesh_config_public(path.as_path(), &config)?;
    }
    if let Some((path, config)) = router_config {
        write_mesh_config_public(path.as_path(), &config)?;
    }

    Ok(state)
}

pub(crate) fn cross_site_router_mesh_bind_ip(
    current_ip: IpAddr,
    fixed_router_mesh_port: Option<u16>,
) -> IpAddr {
    if fixed_router_mesh_port.is_none() {
        return current_ip;
    }
    match current_ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
    }
}

pub(crate) fn allocate_direct_runtime_port(
    reserved: &mut BTreeSet<u16>,
    preferred: Option<u16>,
) -> Result<u16> {
    if let Some(preferred) = preferred {
        if reserved.insert(preferred) {
            return Ok(preferred);
        }
        return Err(miette::miette!(
            "runtime port {} was requested twice in one direct runtime",
            preferred
        ));
    }
    for _ in 0..256 {
        let port = pick_free_port()?;
        if reserved.insert(port) {
            return Ok(port);
        }
    }
    Err(miette::miette!(
        "ran out of ports while allocating direct runtime ports"
    ))
}

pub(crate) fn pick_free_port() -> Result<u16> {
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .into_diagnostic()?;
    Ok(listener.local_addr().into_diagnostic()?.port())
}

pub(crate) fn rewrite_direct_mesh_peer_addrs(
    config: &mut MeshConfigPublic,
    mesh_port_by_peer_id: &HashMap<String, u16>,
) -> Result<()> {
    for route in &mut config.outbound {
        let addr = route.peer_addr.parse::<SocketAddr>().map_err(|err| {
            miette::miette!("invalid mesh peer address {}: {err}", route.peer_addr)
        })?;
        let port = mesh_port_by_peer_id
            .get(route.peer_id.as_str())
            .copied()
            .or_else(|| (addr.port() != 0).then_some(addr.port()))
            .ok_or_else(|| miette::miette!("missing mesh port for peer {}", route.peer_id))?;
        route.peer_addr = SocketAddr::new(addr.ip(), port).to_string();
    }

    for route in &mut config.inbound {
        if let InboundTarget::MeshForward {
            peer_addr, peer_id, ..
        } = &mut route.target
        {
            let addr = peer_addr
                .parse::<SocketAddr>()
                .map_err(|err| miette::miette!("invalid mesh peer address {}: {err}", peer_addr))?;
            let port = mesh_port_by_peer_id
                .get(peer_id.as_str())
                .copied()
                .or_else(|| (addr.port() != 0).then_some(addr.port()))
                .ok_or_else(|| miette::miette!("missing mesh port for peer {}", peer_id))?;
            peer_addr.clear();
            peer_addr.push_str(&SocketAddr::new(addr.ip(), port).to_string());
        }
    }

    Ok(())
}

pub(crate) fn write_direct_runtime_state(
    plan_root: &Path,
    state: &DirectRuntimeState,
) -> Result<()> {
    let path = direct_runtime_state_path(plan_root);
    let parent = path
        .parent()
        .ok_or_else(|| miette::miette!("invalid direct runtime state path"))?;
    fs::create_dir_all(parent)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create direct runtime state dir {}",
                parent.display()
            )
        })?;
    let state = merged_direct_runtime_state_for_write(&path, state);
    let json = serde_json::to_string_pretty(&state)
        .map_err(|err| miette::miette!("failed to serialize direct runtime state: {err}"))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create temporary direct runtime state file in {}",
                parent.display()
            )
        })?;
    temp.write_all(json.as_bytes())
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to write temporary direct runtime state {}",
                path.display()
            )
        })?;
    temp.flush().into_diagnostic().wrap_err_with(|| {
        format!(
            "failed to flush temporary direct runtime state {}",
            path.display()
        )
    })?;
    let _ = temp.persist(&path).map_err(|err| {
        miette::miette!(
            "failed to write direct runtime state {}: {err}",
            path.display()
        )
    })?;
    Ok(())
}

fn merged_direct_runtime_state_for_write(
    path: &Path,
    state: &DirectRuntimeState,
) -> DirectRuntimeState {
    let mut merged = state.clone();
    if merged.router_mesh_port.is_none()
        && let Ok(existing) = read_direct_runtime_state(path)
        && existing.router_mesh_port.is_some()
    {
        merged.router_mesh_port = existing.router_mesh_port;
    }
    merged
}

pub(crate) fn read_direct_runtime_state(path: &Path) -> Result<DirectRuntimeState> {
    let raw = fs::read_to_string(path).map_err(|err| {
        miette::miette!(
            "failed to read direct runtime state {}: {err}",
            path.display()
        )
    })?;
    serde_json::from_str(&raw)
        .map_err(|err| miette::miette!("invalid direct runtime state {}: {err}", path.display()))
}

pub(crate) fn materialize_direct_runtime(
    plan_root: &Path,
    runtime_root: &Path,
    direct_plan: &DirectPlan,
    mesh_plan: &MeshProvisionPlan,
    fixed_router_mesh_port: Option<u16>,
    reuse_existing: bool,
) -> Result<DirectRuntimeState> {
    let empty_peer_ports = BTreeMap::new();
    materialize_direct_runtime_with_existing(
        plan_root,
        runtime_root,
        direct_plan,
        mesh_plan,
        fixed_router_mesh_port,
        DirectExistingMeshState {
            reuse_existing,
            peer_ports_by_id: &empty_peer_ports,
            peer_identities_by_id: &BTreeMap::new(),
        },
    )
}

pub(crate) struct DirectExistingMeshState<'a> {
    pub(crate) reuse_existing: bool,
    pub(crate) peer_ports_by_id: &'a BTreeMap<String, u16>,
    pub(crate) peer_identities_by_id: &'a BTreeMap<String, MeshIdentityPublic>,
}

pub(crate) fn materialize_direct_runtime_with_existing(
    plan_root: &Path,
    runtime_root: &Path,
    direct_plan: &DirectPlan,
    mesh_plan: &MeshProvisionPlan,
    fixed_router_mesh_port: Option<u16>,
    existing: DirectExistingMeshState<'_>,
) -> Result<DirectRuntimeState> {
    let runtime_state_path = direct_runtime_state_path(plan_root);
    if existing.reuse_existing && runtime_state_path.is_file() {
        return read_direct_runtime_state(&runtime_state_path);
    }
    if runtime_state_path.exists() {
        let _ = fs::remove_file(&runtime_state_path);
    }
    let merged_peer_identities =
        merge_existing_mesh_peer_identities(mesh_plan, existing.peer_identities_by_id)?;
    let existing_mesh_peer_identities =
        required_existing_mesh_peer_identities(mesh_plan, &merged_peer_identities)?;
    provision_mesh_filesystem_with_peer_identities(
        mesh_plan,
        runtime_root,
        &existing_mesh_peer_identities,
    )?;
    let runtime_state = if existing.peer_ports_by_id.is_empty() {
        assign_direct_runtime_ports(runtime_root, direct_plan, fixed_router_mesh_port)?
    } else {
        assign_direct_runtime_ports_with_existing(
            runtime_root,
            direct_plan,
            fixed_router_mesh_port,
            existing.peer_ports_by_id,
        )?
    };
    write_direct_runtime_state(plan_root, &runtime_state)?;
    Ok(runtime_state)
}

pub(crate) fn configure_direct_mesh_network(
    runtime_root: &Path,
    runtime_state: &DirectRuntimeState,
    direct_plan: &DirectPlan,
) -> Result<DirectMeshNetworkPlan> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = runtime_root;
        let _ = runtime_state;
        let _ = direct_plan;
        Ok(DirectMeshNetworkPlan::default())
    }

    #[cfg(target_os = "linux")]
    {
        let mut plan = DirectMeshNetworkPlan::default();
        for component in &direct_plan.components {
            let path = runtime_root.join(&component.sidecar.mesh_config_path);
            let mut config = read_mesh_config_public(path.as_path())?;
            let mesh_port = runtime_state
                .component_mesh_port_by_id
                .get(&component.id)
                .copied()
                .ok_or_else(|| {
                    miette::miette!(
                        "missing runtime mesh port for component {}",
                        component.moniker
                    )
                })?;
            plan.component_mesh_port_by_id
                .insert(component.id, mesh_port);
            config.mesh_listen = rewrite_mesh_listen_for_slirp_guest(config.mesh_listen);

            for route in &mut config.outbound {
                route.peer_addr = rewrite_peer_addr_for_slirp_gateway(route.peer_addr.as_str());
            }
            for route in &mut config.inbound {
                if let InboundTarget::MeshForward { peer_addr, .. } = &mut route.target {
                    *peer_addr = rewrite_peer_addr_for_slirp_gateway(peer_addr.as_str());
                }
            }

            write_mesh_config_public(path.as_path(), &config)?;
        }
        Ok(plan)
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn rewrite_mesh_listen_for_slirp_guest(mesh_listen: SocketAddr) -> SocketAddr {
    if mesh_listen.ip().is_loopback() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, mesh_listen.port()))
    } else {
        mesh_listen
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn rewrite_peer_addr_for_slirp_gateway(peer_addr: &str) -> String {
    let Ok(addr) = peer_addr.parse::<SocketAddr>() else {
        return peer_addr.to_string();
    };
    if !addr.ip().is_loopback() {
        return peer_addr.to_string();
    }

    SocketAddr::from((Ipv4Addr::new(10, 0, 2, 2), addr.port())).to_string()
}

#[cfg(target_os = "linux")]
pub(crate) fn rewrite_sidecar_env_passthrough_for_slirp(name: &str, value: &str) -> String {
    if name != amber_mesh::FRAMEWORK_COMPONENT_CONTROLLER_URL_ENV {
        return value.to_string();
    }
    rewrite_loopback_url_for_slirp_gateway(value)
}

#[cfg(target_os = "linux")]
pub(crate) fn rewrite_loopback_url_for_slirp_gateway(value: &str) -> String {
    let Ok(mut url) = Url::parse(value) else {
        return value.to_string();
    };
    let Some(host) = url.host_str() else {
        return value.to_string();
    };
    let is_loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|addr| addr.is_loopback())
            .unwrap_or(false);
    if !is_loopback {
        return value.to_string();
    }
    if url.set_host(Some("10.0.2.2")).is_err() {
        return value.to_string();
    }
    url.to_string()
}

pub(crate) fn read_mesh_config_public(path: &Path) -> Result<MeshConfigPublic> {
    let raw = fs::read_to_string(path)
        .map_err(|err| miette::miette!("failed to read mesh config {}: {err}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|err| miette::miette!("invalid mesh config {}: {err}", path.display()))
}

pub(crate) fn write_mesh_config_public(path: &Path, config: &MeshConfigPublic) -> Result<()> {
    let json = serde_json::to_string_pretty(config).map_err(|err| {
        miette::miette!("failed to serialize mesh config {}: {err}", path.display())
    })?;
    fs::write(path, json)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write mesh config {}", path.display()))
}

#[cfg(test)]
mod tests {
    use amber_mesh::{InboundRoute, MeshPeer};

    use super::*;

    fn mesh_identity_public(id: &str, public_key: [u8; 32]) -> MeshIdentityPublic {
        MeshIdentityPublic {
            id: id.to_string(),
            public_key,
            mesh_scope: Some("amber.test".to_string()),
        }
    }

    #[test]
    fn merge_existing_mesh_peer_identities_keeps_embedded_plan_identities() {
        let embedded_identity = mesh_identity_public("/site/compose/router", [7; 32]);
        let mesh_plan = MeshProvisionPlan {
            version: MESH_PROVISION_PLAN_VERSION.to_string(),
            identity_seed: None,
            existing_peer_identities: vec![embedded_identity.clone()],
            targets: Vec::new(),
        };

        let merged =
            merge_existing_mesh_peer_identities(&mesh_plan, &BTreeMap::new()).expect("merge");

        let merged_identity = merged
            .get("/site/compose/router")
            .expect("embedded identity should remain available");
        assert_eq!(merged_identity.id, embedded_identity.id);
        assert_eq!(merged_identity.public_key, embedded_identity.public_key);
        assert_eq!(merged_identity.mesh_scope, embedded_identity.mesh_scope);
    }

    #[test]
    fn merge_existing_mesh_peer_identities_rejects_conflicts() {
        let mesh_plan = MeshProvisionPlan {
            version: MESH_PROVISION_PLAN_VERSION.to_string(),
            identity_seed: None,
            existing_peer_identities: vec![mesh_identity_public("/peer", [1; 32])],
            targets: Vec::new(),
        };
        let discovered =
            BTreeMap::from([("/peer".to_string(), mesh_identity_public("/peer", [2; 32]))]);

        let err = merge_existing_mesh_peer_identities(&mesh_plan, &discovered)
            .expect_err("conflicting embedded and discovered identities should fail");

        assert!(
            err.to_string()
                .contains("does not match the embedded mesh provision plan"),
            "unexpected merge error: {err}",
        );
    }

    #[test]
    fn rewrite_direct_mesh_peer_addrs_preserves_authored_external_peer_ports() {
        let mut config = MeshConfigPublic {
            identity: mesh_identity_public("/site/direct/router", [3; 32]),
            mesh_listen: "127.0.0.1:24000".parse().expect("mesh listen"),
            control_listen: None,
            dynamic_caps_listen: None,
            control_allow: None,
            peers: vec![MeshPeer {
                id: "/site/compose/router".to_string(),
                public_key: [4; 32],
            }],
            inbound: vec![InboundRoute {
                route_id: "in".to_string(),
                capability: "site-controller".to_string(),
                capability_kind: None,
                capability_profile: None,
                protocol: MeshProtocol::Http,
                http_plugins: Vec::new(),
                target: InboundTarget::MeshForward {
                    peer_addr: "127.0.0.1:32002".to_string(),
                    peer_id: "/site/compose/router".to_string(),
                    route_id: "route".to_string(),
                    capability: "site-controller".to_string(),
                },
                allowed_issuers: Vec::new(),
            }],
            outbound: vec![OutboundRoute {
                route_id: "out".to_string(),
                rewrite_route_id: None,
                slot: "compose".to_string(),
                capability_kind: None,
                capability_profile: None,
                listen_port: 25000,
                listen_addr: None,
                protocol: MeshProtocol::Http,
                http_plugins: Vec::new(),
                peer_addr: "127.0.0.1:32001".to_string(),
                peer_id: "/site/compose/router".to_string(),
                capability: "site-controller".to_string(),
            }],
            transport: amber_mesh::TransportConfig::NoiseIk {},
        };

        rewrite_direct_mesh_peer_addrs(&mut config, &HashMap::new()).expect("rewrite");

        assert_eq!(config.outbound[0].peer_addr, "127.0.0.1:32001");
        let InboundTarget::MeshForward { peer_addr, .. } = &config.inbound[0].target else {
            panic!("expected mesh forward route");
        };
        assert_eq!(peer_addr, "127.0.0.1:32002");
    }

    #[test]
    fn direct_component_control_socket_path_stays_short_on_long_work_dirs() {
        let work_dir = Path::new(
            "/Users/example/Developer/amber/target/cli-test-outputs/\
             mixed-run-doc-example-detach-very-long/state/runs/run-123/state/direct_local/runtime/\
             work/components/c2-web",
        );
        let socket = direct_component_control_socket_path(work_dir, 2);
        let rendered = socket.as_os_str().to_string_lossy();

        assert!(
            rendered.len() < 104,
            "direct sidecar control socket path must fit within unix socket limits: {rendered}",
        );
    }
}
