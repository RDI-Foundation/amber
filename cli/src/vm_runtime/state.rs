use super::*;

pub(crate) fn vm_storage_root(
    plan_root: &Path,
    override_root: Option<&Path>,
) -> std::io::Result<PathBuf> {
    if let Some(override_root) = override_root {
        return Ok(if override_root.is_absolute() {
            override_root.to_path_buf()
        } else {
            env::current_dir()?.join(override_root)
        });
    }

    let name = plan_root
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("amber-vm");
    let parent = plan_root.parent().unwrap_or_else(|| Path::new("."));
    Ok(parent.join(format!(".{name}.amber-state")))
}

pub(crate) fn vm_runtime_state_path(plan_root: &Path) -> PathBuf {
    plan_root.join(".amber").join("vm-runtime.json")
}

pub(crate) fn vm_current_control_socket_path(plan_root: &Path) -> PathBuf {
    hashed_temp_socket_path("amber-vm-control", "current", plan_root)
}

pub(crate) fn vm_runtime_control_socket_path(runtime_root: &Path) -> PathBuf {
    hashed_temp_socket_path("amber-vm-control", "runtime", runtime_root)
}

pub(crate) fn canonicalize_path(path: &Path, description: &str) -> Result<PathBuf> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir().into_diagnostic()?.join(path)
    };
    abs.canonicalize()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to resolve {description} path {}", abs.display()))
}

pub(crate) fn read_json_file<T>(path: &Path, description: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let raw = fs::read_to_string(path).map_err(|err| {
        miette::miette!("failed to read {} {}: {err}", description, path.display())
    })?;
    serde_json::from_str(&raw)
        .map_err(|err| miette::miette!("invalid {} {}: {err}", description, path.display()))
}

pub(crate) fn read_vm_runtime_state(path: &Path) -> Result<VmRuntimeState> {
    read_json_file(path, "vm runtime state")
}

pub(crate) fn write_vm_runtime_state(plan_root: &Path, state: &VmRuntimeState) -> Result<()> {
    let path = vm_runtime_state_path(plan_root);
    let parent = path
        .parent()
        .ok_or_else(|| miette::miette!("invalid vm runtime state path"))?;
    fs::create_dir_all(parent)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create vm runtime state dir {}", parent.display()))?;
    let state = merged_vm_runtime_state_for_write(&path, state);
    let json = serde_json::to_string_pretty(&state)
        .map_err(|err| miette::miette!("failed to serialize vm runtime state: {err}"))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create temporary vm runtime state file in {}",
                parent.display()
            )
        })?;
    temp.write_all(json.as_bytes())
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to write temporary vm runtime state {}",
                path.display()
            )
        })?;
    temp.flush().into_diagnostic().wrap_err_with(|| {
        format!(
            "failed to flush temporary vm runtime state {}",
            path.display()
        )
    })?;
    let _ = temp.persist(&path).map_err(|err| {
        miette::miette!("failed to write vm runtime state {}: {err}", path.display())
    })?;
    Ok(())
}

fn merged_vm_runtime_state_for_write(path: &Path, state: &VmRuntimeState) -> VmRuntimeState {
    let mut merged = state.clone();
    if merged.router_mesh_port.is_none()
        && let Ok(existing) = read_vm_runtime_state(path)
        && existing.router_mesh_port.is_some()
    {
        merged.router_mesh_port = existing.router_mesh_port;
    }
    merged
}

pub(crate) fn materialize_vm_runtime(
    plan_root: &Path,
    runtime_root: &Path,
    vm_plan: &VmPlan,
    mesh_plan: &MeshProvisionPlan,
    fixed_router_mesh_port: Option<u16>,
    reuse_existing: bool,
) -> Result<VmPortAssignments> {
    let empty_peer_ports = BTreeMap::new();
    let empty_peer_identities = BTreeMap::new();
    materialize_vm_runtime_with_existing(
        plan_root,
        runtime_root,
        vm_plan,
        mesh_plan,
        fixed_router_mesh_port,
        VmExistingMeshState {
            reuse_existing,
            peer_ports_by_id: &empty_peer_ports,
            peer_identities_by_id: &empty_peer_identities,
        },
    )
}

pub(crate) struct VmExistingMeshState<'a> {
    pub(crate) reuse_existing: bool,
    pub(crate) peer_ports_by_id: &'a BTreeMap<String, u16>,
    pub(crate) peer_identities_by_id: &'a BTreeMap<String, MeshIdentityPublic>,
}

pub(crate) fn materialize_vm_runtime_with_existing(
    plan_root: &Path,
    runtime_root: &Path,
    vm_plan: &VmPlan,
    mesh_plan: &MeshProvisionPlan,
    fixed_router_mesh_port: Option<u16>,
    existing: VmExistingMeshState<'_>,
) -> Result<VmPortAssignments> {
    let runtime_state_path = vm_runtime_state_path(plan_root);
    if existing.reuse_existing && runtime_state_path.is_file() {
        let state = read_vm_runtime_state(&runtime_state_path)?;
        return Ok(VmPortAssignments {
            route_host_ports_by_component: state.route_host_ports_by_component.clone(),
            state,
        });
    }
    if runtime_state_path.exists() {
        let _ = fs::remove_file(&runtime_state_path);
    }
    let existing_mesh_peer_identities =
        crate::direct_runtime::required_existing_mesh_peer_identities(
            mesh_plan,
            existing.peer_identities_by_id,
        )?;
    crate::direct_runtime::provision_mesh_filesystem_with_peer_identities(
        mesh_plan,
        runtime_root,
        &existing_mesh_peer_identities,
    )?;
    let assignments = if existing.peer_ports_by_id.is_empty() {
        assign_vm_runtime_ports(runtime_root, vm_plan, fixed_router_mesh_port)?
    } else {
        assign_vm_runtime_ports_with_existing(
            runtime_root,
            vm_plan,
            fixed_router_mesh_port,
            existing.peer_ports_by_id,
        )?
    };
    write_vm_runtime_state(plan_root, &assignments.state)?;
    Ok(assignments)
}

pub(crate) fn hashed_temp_socket_path(namespace: &str, kind: &str, path: &Path) -> PathBuf {
    amber_mesh::stable_temp_socket_path(namespace, kind, path)
}

fn vm_component_control_socket_path(work_dir: &Path, component_id: usize) -> PathBuf {
    hashed_temp_socket_path(
        "amber-vm-control",
        &format!("sidecar-{component_id}"),
        work_dir,
    )
}

pub(crate) fn assign_vm_runtime_ports(
    runtime_root: &Path,
    vm_plan: &VmPlan,
    fixed_router_mesh_port: Option<u16>,
) -> Result<VmPortAssignments> {
    assign_vm_runtime_ports_with_existing(
        runtime_root,
        vm_plan,
        fixed_router_mesh_port,
        &BTreeMap::new(),
    )
}

pub(crate) fn assign_vm_runtime_ports_with_existing(
    runtime_root: &Path,
    vm_plan: &VmPlan,
    fixed_router_mesh_port: Option<u16>,
    existing_peer_ports_by_id: &BTreeMap<String, u16>,
) -> Result<VmPortAssignments> {
    let mut state = VmRuntimeState::default();
    let mut reserved = BTreeSet::new();
    let mut mesh_port_by_peer_id = HashMap::<String, u16>::new();
    let mut component_configs = Vec::<(PathBuf, MeshConfigPublic)>::new();
    let mut route_host_ports_by_component = BTreeMap::<usize, BTreeMap<String, Vec<u16>>>::new();

    for (peer_id, port) in existing_peer_ports_by_id {
        if !reserved.insert(*port) {
            return Err(miette::miette!(
                "runtime port {} was requested twice in one vm runtime",
                port
            ));
        }
        mesh_port_by_peer_id.insert(peer_id.clone(), *port);
    }

    for component in &vm_plan.components {
        let path = runtime_root.join(&component.mesh_config_path);
        let mut config = read_mesh_config_public(&path)?;
        let mesh_port = allocate_runtime_port(&mut reserved, None)?;
        if mesh_port_by_peer_id
            .insert(config.identity.id.clone(), mesh_port)
            .is_some()
        {
            return Err(miette::miette!(
                "mesh peer id {} was registered twice in one vm runtime",
                config.identity.id
            ));
        }
        config.mesh_listen = SocketAddr::new(config.mesh_listen.ip(), mesh_port);

        let mut route_guest_host_pairs = BTreeMap::<String, Vec<(u16, u16)>>::new();
        for route in &mut config.outbound {
            let guest_port = route.listen_port;
            let host_port = allocate_runtime_port(&mut reserved, None)?;
            route.listen_port = host_port;
            route_guest_host_pairs
                .entry(route.slot.clone())
                .or_default()
                .push((guest_port, host_port));
        }
        for ports in route_guest_host_pairs.values_mut() {
            ports.sort_unstable_by_key(|(guest_port, _)| *guest_port);
        }
        let slot_guest_ports = route_guest_host_pairs
            .iter()
            .map(|(slot, pairs)| {
                (
                    slot.clone(),
                    pairs
                        .iter()
                        .map(|(guest_port, _)| *guest_port)
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let slot_host_ports = route_guest_host_pairs
            .into_iter()
            .map(|(slot, pairs)| {
                (
                    slot,
                    pairs
                        .into_iter()
                        .map(|(_, host_port)| host_port)
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<BTreeMap<_, _>>();

        let mut endpoint_forwards = BTreeMap::new();
        for route in &mut config.inbound {
            if let InboundTarget::Local { ref mut port } = route.target {
                let guest_port = *port;
                let host_port = if let Some(existing) = endpoint_forwards.get(&guest_port) {
                    *existing
                } else {
                    let host_port = allocate_runtime_port(&mut reserved, None)?;
                    endpoint_forwards.insert(guest_port, host_port);
                    host_port
                };
                *port = host_port;
            }
        }

        let slot_ports = slot_guest_ports
            .iter()
            .filter_map(|(slot, ports)| (ports.len() == 1).then_some((slot.clone(), ports[0])))
            .collect::<BTreeMap<_, _>>();

        state
            .component_mesh_port_by_id
            .insert(component.id, mesh_port);
        state
            .slot_ports_by_component
            .insert(component.id, slot_ports);
        state
            .slot_route_ports_by_component
            .insert(component.id, slot_guest_ports);
        state
            .route_host_ports_by_component
            .insert(component.id, slot_host_ports.clone());
        state
            .endpoint_forwards_by_component
            .insert(component.id, endpoint_forwards);
        route_host_ports_by_component.insert(component.id, slot_host_ports);
        component_configs.push((path, config));
    }

    let mut router_config = if let Some(router) = vm_plan.router.as_ref() {
        let path = runtime_root.join(&router.mesh_config_path);
        let mut config = read_mesh_config_public(&path)?;
        let mesh_port = allocate_runtime_port(&mut reserved, fixed_router_mesh_port)?;
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
        rewrite_mesh_peer_addrs(config, &mesh_port_by_peer_id)?;
    }
    if let Some((_, config)) = router_config.as_mut() {
        rewrite_mesh_peer_addrs(config, &mesh_port_by_peer_id)?;
    }

    for (path, config) in component_configs {
        write_mesh_config_public(&path, &config)?;
    }
    if let Some((path, config)) = router_config {
        write_mesh_config_public(&path, &config)?;
    }

    Ok(VmPortAssignments {
        state,
        route_host_ports_by_component,
    })
}

pub(crate) fn allocate_runtime_port(
    reserved: &mut BTreeSet<u16>,
    preferred: Option<u16>,
) -> Result<u16> {
    if let Some(preferred) = preferred {
        if reserved.insert(preferred) {
            return Ok(preferred);
        }
        return Err(miette::miette!(
            "runtime port {} was requested twice in one vm runtime",
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
        "ran out of ports while allocating vm runtime ports"
    ))
}

pub(crate) fn pick_free_port() -> Result<u16> {
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .into_diagnostic()?;
    Ok(listener.local_addr().into_diagnostic()?.port())
}

pub(crate) fn rewrite_mesh_peer_addrs(
    config: &mut MeshConfigPublic,
    mesh_port_by_peer_id: &HashMap<String, u16>,
) -> Result<()> {
    for route in &mut config.outbound {
        let port = mesh_port_by_peer_id
            .get(route.peer_id.as_str())
            .copied()
            .ok_or_else(|| miette::miette!("missing mesh port for peer {}", route.peer_id))?;
        let addr = route.peer_addr.parse::<SocketAddr>().map_err(|err| {
            miette::miette!("invalid mesh peer address {}: {err}", route.peer_addr)
        })?;
        route.peer_addr = SocketAddr::new(addr.ip(), port).to_string();
    }

    for route in &mut config.inbound {
        if let InboundTarget::MeshForward {
            ref mut peer_addr,
            ref peer_id,
            ..
        } = route.target
        {
            let port = mesh_port_by_peer_id
                .get(peer_id.as_str())
                .copied()
                .ok_or_else(|| miette::miette!("missing mesh port for peer {}", peer_id))?;
            let addr = peer_addr
                .parse::<SocketAddr>()
                .map_err(|err| miette::miette!("invalid mesh peer address {}: {err}", peer_addr))?;
            *peer_addr = SocketAddr::new(addr.ip(), port).to_string();
        }
    }

    Ok(())
}

pub(crate) fn read_mesh_config_public(path: &Path) -> Result<MeshConfigPublic> {
    read_json_file(path, "mesh config")
}

pub(crate) fn write_mesh_config_public(path: &Path, config: &MeshConfigPublic) -> Result<()> {
    let json = serde_json::to_string_pretty(config).map_err(|err| {
        miette::miette!("failed to serialize mesh config {}: {err}", path.display())
    })?;
    fs::write(path, json)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write mesh config {}", path.display()))
}

pub(crate) fn project_existing_vm_peer_identities(
    runtime_root: &Path,
    vm_plan: &VmPlan,
    existing_peer_identities_by_id: &BTreeMap<String, MeshIdentityPublic>,
) -> Result<()> {
    if existing_peer_identities_by_id.is_empty() {
        return Ok(());
    }
    for component in &vm_plan.components {
        crate::project_existing_peer_identities_into_mesh_config(
            &runtime_root.join(&component.mesh_config_path),
            existing_peer_identities_by_id,
        )?;
    }
    if let Some(router) = vm_plan.router.as_ref() {
        crate::project_existing_peer_identities_into_mesh_config(
            &runtime_root.join(&router.mesh_config_path),
            existing_peer_identities_by_id,
        )?;
    } else {
        crate::project_existing_peer_identities_into_mesh_config(
            &runtime_root.join("mesh/router").join(MESH_CONFIG_FILENAME),
            existing_peer_identities_by_id,
        )?;
    }
    Ok(())
}

pub(crate) async fn spawn_vm_router(
    router_binary: &str,
    runtime_root: &Path,
    plan_root: &Path,
    router: &VmRouterPlan,
    children: &mut Vec<ManagedChild>,
    log_tasks: &mut Vec<tokio::task::JoinHandle<()>>,
) -> Result<VmControlSocketPaths> {
    let paths = VmControlSocketPaths {
        artifact_link: resolve_artifact_path(plan_root, &router.control_socket_path),
        current_link: vm_current_control_socket_path(plan_root),
        runtime: vm_runtime_control_socket_path(runtime_root),
    };
    let artifact_dir = paths
        .artifact_link
        .parent()
        .ok_or_else(|| miette::miette!("invalid vm control socket path"))?;
    let current_dir = paths
        .current_link
        .parent()
        .ok_or_else(|| miette::miette!("invalid current vm control socket path"))?;
    let runtime_dir = paths
        .runtime
        .parent()
        .ok_or_else(|| miette::miette!("invalid runtime vm control socket path"))?;
    fs::create_dir_all(artifact_dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create vm control dir {}", artifact_dir.display()))?;
    fs::create_dir_all(current_dir)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create current vm control dir {}",
                current_dir.display()
            )
        })?;
    fs::create_dir_all(runtime_dir)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create runtime vm control dir {}",
                runtime_dir.display()
            )
        })?;
    if paths.runtime.exists() {
        fs::remove_file(&paths.runtime)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "failed to remove stale runtime vm control socket {}",
                    paths.runtime.display()
                )
            })?;
    }
    ensure_control_socket_link(
        &paths.artifact_link,
        &paths.current_link,
        "vm router control symlink",
    )?;
    ensure_control_socket_link(
        &paths.current_link,
        &paths.runtime,
        "runtime vm router control symlink",
    )?;

    let mut env_map = BTreeMap::new();
    env_map.insert(
        "AMBER_ROUTER_CONFIG_PATH".to_string(),
        runtime_root
            .join(&router.mesh_config_path)
            .display()
            .to_string(),
    );
    env_map.insert(
        "AMBER_ROUTER_IDENTITY_PATH".to_string(),
        runtime_root
            .join(&router.mesh_identity_path)
            .display()
            .to_string(),
    );
    env_map.insert(
        "AMBER_ROUTER_CONTROL_SOCKET_PATH".to_string(),
        paths.runtime.display().to_string(),
    );
    for passthrough in &router.env_passthrough {
        if let Ok(value) = env::var(passthrough) {
            env_map.insert(passthrough.clone(), value);
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

    spawn_command(
        "router".to_string(),
        vec![router_binary.to_string()],
        &work_dir,
        env_map,
        ManagedChildShutdown::Signal,
        children,
        log_tasks,
    )
    .await?;

    Ok(paths)
}

pub(crate) async fn spawn_component_sidecar(
    router_binary: &str,
    runtime_root: &Path,
    component: &VmComponentPlan,
    children: &mut Vec<ManagedChild>,
    log_tasks: &mut Vec<tokio::task::JoinHandle<()>>,
) -> Result<()> {
    let mut env_map = BTreeMap::new();
    env_map.insert(
        "AMBER_ROUTER_CONFIG_PATH".to_string(),
        runtime_root
            .join(&component.mesh_config_path)
            .display()
            .to_string(),
    );
    env_map.insert(
        "AMBER_ROUTER_IDENTITY_PATH".to_string(),
        runtime_root
            .join(&component.mesh_identity_path)
            .display()
            .to_string(),
    );
    let work_dir = runtime_root
        .join("work")
        .join("sidecars")
        .join(&component.log_name);
    fs::create_dir_all(&work_dir)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create sidecar runtime directory {}",
                work_dir.display()
            )
        })?;
    let control_socket_path = vm_component_control_socket_path(&work_dir, component.id);
    let control_socket_dir = control_socket_path
        .parent()
        .ok_or_else(|| miette::miette!("invalid vm sidecar control socket path"))?
        .to_path_buf();
    fs::create_dir_all(&control_socket_dir)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create vm sidecar control directory {}",
                control_socket_dir.display()
            )
        })?;
    if control_socket_path.exists() {
        fs::remove_file(&control_socket_path)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "failed to remove stale vm sidecar control socket {}",
                    control_socket_path.display()
                )
            })?;
    }
    env_map.insert(
        "AMBER_ROUTER_CONTROL_SOCKET_PATH".to_string(),
        control_socket_path.display().to_string(),
    );
    spawn_command(
        format!("{}-sidecar", component.log_name),
        vec![router_binary.to_string()],
        &work_dir,
        env_map,
        ManagedChildShutdown::Signal,
        children,
        log_tasks,
    )
    .await?;
    Ok(())
}

pub(crate) fn resolve_artifact_path(plan_root: &Path, path: &str) -> PathBuf {
    let path = Path::new(path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        plan_root.join(path)
    }
}

#[cfg(unix)]
pub(crate) fn ensure_control_socket_link(
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
pub(crate) fn ensure_control_socket_link(
    link: &Path,
    target: &Path,
    description: &str,
) -> Result<()> {
    let _ = (link, target, description);
    Err(miette::miette!(
        "vm runtime control sockets require unix symlink support"
    ))
}

pub(crate) fn remove_control_socket_link(paths: &VmControlSocketPaths) {
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

pub(crate) async fn cleanup_vm_runtime(
    children: &mut [ManagedChild],
    log_tasks: Vec<tokio::task::JoinHandle<()>>,
    runtime_state_path: &Path,
    control_socket_paths: Option<&VmControlSocketPaths>,
    runtime_dir: Option<tempfile::TempDir>,
) {
    terminate_children(children).await;
    for task in log_tasks {
        let _ = task.await;
    }
    if let Some(paths) = control_socket_paths {
        remove_control_socket_link(paths);
        let _ = fs::remove_file(&paths.runtime);
    }
    let _ = fs::remove_file(runtime_state_path);
    drop(runtime_dir);
}

pub(crate) fn render_mount_files(
    mount_spec_b64: Option<&str>,
    component_config: Option<&Value>,
    component_schema: Option<&Value>,
    runtime_context: &RuntimeTemplateContext,
) -> Result<Vec<RenderedMountFile>> {
    let Some(mount_spec_b64) = mount_spec_b64 else {
        return Ok(Vec::new());
    };
    let mounts = decode_b64_json_t::<Vec<MountSpec>>("AMBER_MOUNT_SPEC_B64", mount_spec_b64)?;
    let mut rendered = Vec::with_capacity(mounts.len());
    for (path, contents) in
        render_mount_specs(&mounts, component_config, component_schema, runtime_context)
            .map_err(|err| miette::miette!("{err}"))?
    {
        if !Path::new(&path).is_absolute() {
            return Err(miette::miette!(
                "vm mount path {} must be absolute",
                Path::new(&path).display()
            ));
        }
        rendered.push(RenderedMountFile {
            guest_path: path,
            contents,
        });
    }
    Ok(rendered)
}

pub(crate) fn build_component_config(
    payload: Option<&DirectRuntimeConfigPayload>,
    runtime_context: &RuntimeTemplateContext,
) -> Result<Option<(Value, Value)>> {
    let Some(payload) = payload else {
        return Ok(None);
    };
    let root_schema = decode_b64_json("AMBER_ROOT_CONFIG_SCHEMA_B64", &payload.root_schema_b64)?;
    let component_schema = decode_b64_json(
        "AMBER_COMPONENT_CONFIG_SCHEMA_B64",
        &payload.component_schema_b64,
    )?;
    let component_template_value = decode_b64_json(
        "AMBER_COMPONENT_CONFIG_TEMPLATE_B64",
        &payload.component_cfg_template_b64,
    )?;
    let component_template = ConfigTemplatePayload::from_value(component_template_value)
        .map_err(|err| miette::miette!("invalid component config template: {err}"))?;

    let mut config_env = BTreeMap::new();
    for path in &payload.allowed_root_leaf_paths {
        let env_var = env_var_for_path(path)
            .map_err(|err| miette::miette!("failed to map config path {}: {err}", path))?;
        if let Ok(value) = env::var(&env_var) {
            config_env.insert(env_var, value);
        }
    }
    let component_config = resolve_runtime_component_config(
        &root_schema,
        &component_schema,
        &component_template,
        &config_env,
        runtime_context,
    )
    .map_err(|err| miette::miette!("failed to resolve runtime component config: {err}"))?;

    Ok(Some((component_config, component_schema)))
}

pub(crate) fn build_vm_runtime_template_context(
    runtime_addresses: &DirectRuntimeAddressPlan,
    runtime_state: &VmRuntimeState,
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
                        "failed to serialize vm runtime slot object for scope {} slot {}: {err}",
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
    runtime_state: &VmRuntimeState,
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
                        "missing vm runtime slot port for component {} slot {}",
                        component_id,
                        slot
                    )
                })?;
            Ok(format!("{scheme}://{VM_RUNTIME_SLOT_HOST}:{port}"))
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
                        "missing vm runtime slot item {} for component {} slot {}",
                        item_index,
                        component_id,
                        slot
                    )
                })?;
            Ok(format!("{scheme}://{VM_RUNTIME_SLOT_HOST}:{port}"))
        }
    }
}

pub(crate) fn wait_for_guestfwd_targets(
    component: &VmComponentPlan,
    port_assignments: &VmPortAssignments,
    timeout: Duration,
) -> Result<()> {
    let Some(slot_ports) = port_assignments
        .route_host_ports_by_component
        .get(&component.id)
    else {
        return Ok(());
    };
    for ports in slot_ports.values() {
        for port in ports {
            wait_for_stable_endpoint(SocketAddr::from(([127, 0, 0, 1], *port)), timeout).map_err(
                |err| {
                    miette::miette!(
                        "guestfwd target 127.0.0.1:{} for component {} did not become ready: {err}",
                        port,
                        component.moniker
                    )
                },
            )?;
        }
    }
    Ok(())
}

pub(crate) fn wait_for_endpoint_forwards(
    component: &VmComponentPlan,
    runtime_root: &Path,
    timeout: Duration,
    child: &mut ManagedChild,
) -> Result<()> {
    let config = read_mesh_config_public(&runtime_root.join(&component.mesh_config_path))?;
    for route in config.inbound {
        let InboundTarget::Local { port: host_port } = route.target else {
            continue;
        };
        let addr = SocketAddr::from(([127, 0, 0, 1], host_port));
        wait_for_endpoint_or_child_exit(
            child,
            addr,
            timeout,
            match route.protocol {
                MeshProtocol::Http => endpoint_returns_http_response,
                MeshProtocol::Tcp => endpoint_accepts_stable_connection,
            },
        )
        .map_err(|err| match route.protocol {
            MeshProtocol::Http => {
                miette::miette!(
                    "forwarded HTTP endpoint 127.0.0.1:{} for component {} did not become ready: \
                     {err}",
                    host_port,
                    component.moniker
                )
            }
            MeshProtocol::Tcp => {
                miette::miette!(
                    "forwarded TCP endpoint 127.0.0.1:{} for component {} did not become ready: \
                     {err}",
                    host_port,
                    component.moniker
                )
            }
        })?;
    }
    Ok(())
}

pub(crate) fn wait_for_endpoint_or_child_exit(
    child: &mut ManagedChild,
    addr: SocketAddr,
    timeout: Duration,
    probe: fn(SocketAddr, Duration, Duration) -> bool,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if probe(addr, Duration::from_millis(250), Duration::from_millis(250)) {
            return Ok(());
        }
        if let Some(status) = child.child.try_wait().into_diagnostic()? {
            return Err(miette::miette!(
                "vm process {} exited before endpoint {} became ready with status {}",
                child.name,
                addr,
                status
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(miette::miette!("timeout after {:?}", timeout))
}

pub(crate) fn vm_endpoint_forward_ready_timeout() -> Duration {
    if vm_uses_tcg_accel() {
        TCG_VM_STARTUP_TIMEOUT
    } else {
        Duration::from_secs(120)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_vm_runtime_state_preserves_projected_router_mesh_port() {
        let plan_root = tempfile::tempdir().expect("temp dir should be created");
        let existing = VmRuntimeState {
            router_mesh_port: Some(25000),
            component_mesh_port_by_id: BTreeMap::from([(1, 21001)]),
            ..Default::default()
        };
        write_vm_runtime_state(plan_root.path(), &existing)
            .expect("existing vm runtime state should be written");

        let replacement = VmRuntimeState {
            component_mesh_port_by_id: BTreeMap::from([(2, 21002)]),
            ..Default::default()
        };
        write_vm_runtime_state(plan_root.path(), &replacement)
            .expect("replacement vm runtime state should be written");

        let persisted = read_vm_runtime_state(&vm_runtime_state_path(plan_root.path()))
            .expect("persisted vm runtime state should be readable");
        assert_eq!(persisted.router_mesh_port, Some(25000));
        assert_eq!(
            persisted.component_mesh_port_by_id,
            replacement.component_mesh_port_by_id
        );
    }

    #[test]
    fn vm_component_control_socket_path_stays_short_on_long_work_dirs() {
        let work_dir = Path::new(
            "/Users/example/Developer/amber/target/cli-test-outputs/\
             linux-vm-framework_component-very-long/state/runs/run-123/state/vm_local/runtime/\
             work/sidecars/c2-web",
        );
        let socket = vm_component_control_socket_path(work_dir, 2);
        let rendered = socket.as_os_str().to_string_lossy();

        assert!(
            rendered.len() < 104,
            "vm sidecar control socket path must fit within unix socket limits: {rendered}",
        );
    }
}
