use super::*;

pub(super) fn dynamic_compose_mesh_dir(service_name: &str) -> String {
    format!("{DYNAMIC_COMPOSE_MESH_ROOT}/{service_name}")
}

pub(super) fn filter_dynamic_router_target(
    router_target: &mut amber_mesh::MeshProvisionTarget,
    kept_component_ids: &BTreeSet<String>,
) {
    router_target
        .config
        .peers
        .retain(|peer| kept_component_ids.contains(&peer.id));
    router_target
        .config
        .inbound
        .retain(|route| match &route.target {
            InboundTarget::MeshForward { peer_id, .. } => kept_component_ids.contains(peer_id),
            _ => route
                .allowed_issuers
                .iter()
                .any(|issuer| kept_component_ids.contains(issuer)),
        });
}

pub(super) fn dynamic_proxy_export_mesh_protocol(
    export: &DynamicProxyExportRecord,
) -> Result<MeshProtocol> {
    let protocol = export
        .protocol
        .parse::<NetworkProtocol>()
        .map_err(|err| miette::miette!("invalid dynamic proxy export protocol: {err}"))?;
    mesh_protocol(protocol)
}

pub(super) fn dynamic_proxy_export_http_plugins(
    export: &DynamicProxyExportRecord,
    protocol: MeshProtocol,
) -> Vec<HttpRoutePlugin> {
    matches!(
        (export.capability_kind.as_str(), protocol),
        ("a2a", MeshProtocol::Http)
    )
    .then_some(HttpRoutePlugin::A2a)
    .into_iter()
    .collect()
}

pub(super) fn dynamic_proxy_export_route_id(
    export_name: &str,
    export: &DynamicProxyExportRecord,
) -> Result<String> {
    Ok(router_dynamic_export_route_id(
        &export.component,
        export_name,
        dynamic_proxy_export_mesh_protocol(export)?,
    ))
}

pub(super) fn dynamic_input_direct_mesh_protocol(
    input: &DynamicInputDirectRecord,
) -> Result<MeshProtocol> {
    let protocol = input
        .protocol
        .parse::<NetworkProtocol>()
        .map_err(|err| miette::miette!("invalid dynamic direct-input protocol: {err}"))?;
    mesh_protocol(protocol)
}

pub(super) fn dynamic_input_direct_route_id(
    input: &DynamicInputDirectRecord,
    protocol: MeshProtocol,
) -> String {
    match &input.target {
        DynamicInputRouteTarget::ComponentProvide { provide } => {
            component_route_id(&input.provider_component, provide, protocol)
        }
    }
}

pub(super) fn dynamic_input_direct_capability(input: &DynamicInputDirectRecord) -> String {
    match &input.target {
        DynamicInputRouteTarget::ComponentProvide { provide } => provide.clone(),
    }
}

pub(super) fn is_compose_component_sidecar_service(service_name: &str) -> bool {
    service_name.ends_with("-net")
}

pub(super) fn dynamic_input_direct_http_plugins(
    input: &DynamicInputDirectRecord,
    protocol: MeshProtocol,
) -> Vec<HttpRoutePlugin> {
    dynamic_proxy_export_http_plugins(
        &DynamicProxyExportRecord {
            component_id: 0,
            component: input.provider_component.clone(),
            provide: dynamic_input_direct_capability(input),
            protocol: input.protocol.clone(),
            capability_kind: input.capability_kind.clone(),
            capability_profile: input.capability_profile.clone(),
            target_port: 0,
        },
        protocol,
    )
}

pub(super) fn overlay_peer_addr_map_from_ports(
    ports: &BTreeMap<String, u16>,
) -> BTreeMap<String, String> {
    ports
        .iter()
        .map(|(component, port)| (component.clone(), format!("127.0.0.1:{port}")))
        .collect()
}

pub(super) fn overlay_upsert_peer(
    peers: &mut Vec<MeshPeer>,
    peer_identities: &BTreeMap<String, MeshIdentityPublic>,
    peer_id: &str,
) -> Result<()> {
    if peers.iter().any(|peer| peer.id == peer_id) {
        return Ok(());
    }
    let identity = peer_identities.get(peer_id).ok_or_else(|| {
        miette::miette!("dynamic route overlay is missing mesh identity for peer {peer_id}")
    })?;
    peers.push(MeshPeer {
        id: identity.id.clone(),
        public_key: identity.public_key,
    });
    Ok(())
}

pub(super) fn augment_route_overlay_payload(
    payload: &mut StoredRouteOverlayPayload,
    proxy_exports: &BTreeMap<String, DynamicProxyExportRecord>,
    provider_peer_addrs: &BTreeMap<String, String>,
    peer_identities: &BTreeMap<String, MeshIdentityPublic>,
) -> Result<()> {
    for export in proxy_exports.values() {
        overlay_upsert_peer(&mut payload.peers, peer_identities, &export.component)?;
    }
    add_dynamic_proxy_export_overlay_routes(
        &mut payload.inbound_routes,
        proxy_exports,
        |export| {
            provider_peer_addrs
                .get(&export.component)
                .cloned()
                .ok_or_else(|| {
                    miette::miette!(
                        "dynamic route overlay is missing a live peer address for {}",
                        export.component
                    )
                })
        },
    )?;

    Ok(())
}

pub(super) fn rewrite_dynamic_direct_inputs(
    mesh_plan: &mut MeshProvisionPlan,
    direct_inputs: &[DynamicInputDirectRecord],
    live_components: &BTreeMap<String, LiveComponentRuntimeMetadata>,
) -> Result<()> {
    if direct_inputs.is_empty() {
        return Ok(());
    }

    for input in direct_inputs {
        let provider_runtime = live_components
            .get(&input.provider_component)
            .ok_or_else(|| {
                miette::miette!(
                    "dynamic direct input {}.{} references live provider {} that is unavailable",
                    input.component,
                    input.slot,
                    input.provider_component
                )
            })?;
        let protocol = dynamic_input_direct_mesh_protocol(input)?;
        let component_target = mesh_plan
            .targets
            .iter_mut()
            .find(|target| {
                matches!(target.kind, MeshProvisionTargetKind::Component)
                    && target.config.identity.id == input.component
            })
            .ok_or_else(|| {
                miette::miette!(
                    "dynamic direct input {}.{} is missing component {} in the mesh provision plan",
                    input.component,
                    input.slot,
                    input.component
                )
            })?;
        if !component_target
            .config
            .peers
            .iter()
            .any(|peer| peer.id == provider_runtime.mesh_config.identity.id)
        {
            component_target
                .config
                .peers
                .push(amber_mesh::MeshPeerTemplate {
                    id: provider_runtime.mesh_config.identity.id.clone(),
                });
        }

        let route_id = dynamic_input_direct_route_id(input, protocol);
        let capability = dynamic_input_direct_capability(input);
        let mut matched = false;
        for route in component_target
            .config
            .outbound
            .iter_mut()
            .filter(|route| route.slot == input.slot)
        {
            matched = true;
            route.route_id = route_id.clone();
            route.protocol = protocol;
            route.peer_addr = provider_runtime.component_reachable_mesh_addr.clone();
            route.peer_id = provider_runtime.mesh_config.identity.id.clone();
            route.capability = capability.clone();
            route.capability_kind = Some(input.capability_kind.clone());
            route.capability_profile = input.capability_profile.clone();
            route.http_plugins = dynamic_input_direct_http_plugins(input, protocol);
        }
        if !matched {
            return Err(miette::miette!(
                "dynamic direct input {}.{} is missing an outbound route in the mesh provision \
                 plan",
                input.component,
                input.slot
            ));
        }
    }

    Ok(())
}

pub(super) fn rewrite_dynamic_direct_inputs_in_artifact(
    artifact_root: &Path,
    direct_inputs: &[DynamicInputDirectRecord],
    live_components: &BTreeMap<String, LiveComponentRuntimeMetadata>,
) -> Result<()> {
    if direct_inputs.is_empty() {
        return Ok(());
    }
    let path = artifact_root.join("mesh-provision-plan.json");
    let mut mesh_plan: MeshProvisionPlan = read_json(&path, "mesh provision plan")?;
    rewrite_dynamic_direct_inputs(&mut mesh_plan, direct_inputs, live_components)?;
    write_json(&path, &mesh_plan)
}

pub(super) fn build_filesystem_route_overlay_base(
    artifact_root: &Path,
    assigned_components: &[String],
    provider_peer_addrs: &BTreeMap<String, String>,
    peer_identities: &BTreeMap<String, MeshIdentityPublic>,
) -> Result<StoredRouteOverlayPayload> {
    let mesh_plan: MeshProvisionPlan = read_json(
        &artifact_root.join("mesh-provision-plan.json"),
        "mesh provision plan",
    )?;
    let kept_component_ids = assigned_components.iter().cloned().collect::<BTreeSet<_>>();
    let mut router_target = mesh_plan
        .targets
        .iter()
        .find(|target| matches!(target.kind, MeshProvisionTargetKind::Router))
        .cloned()
        .ok_or_else(|| {
            miette::miette!(
                "dynamic artifact {} is missing a router mesh target",
                artifact_root.display()
            )
        })?;
    filter_dynamic_router_target(&mut router_target, &kept_component_ids);
    for route in &mut router_target.config.inbound {
        if let InboundTarget::MeshForward {
            peer_id, peer_addr, ..
        } = &mut route.target
            && let Some(resolved) = provider_peer_addrs.get(peer_id)
        {
            *peer_addr = resolved.clone();
        }
    }
    let peers = router_target
        .config
        .peers
        .iter()
        .map(|peer| {
            peer_identities.get(&peer.id).map(|identity| MeshPeer {
                id: identity.id.clone(),
                public_key: identity.public_key,
            })
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| {
            miette::miette!(
                "dynamic artifact {} is missing a live mesh identity for one of its route peers",
                artifact_root.display()
            )
        })?;
    Ok(StoredRouteOverlayPayload {
        peers,
        inbound_routes: router_target.config.inbound,
    })
}

pub(super) fn write_direct_vm_live_route_overlay_payload(
    artifact_root: &Path,
    assigned_components: &[String],
    proxy_exports: &BTreeMap<String, DynamicProxyExportRecord>,
    provider_peer_addrs: &BTreeMap<String, String>,
    peer_identities: &BTreeMap<String, MeshIdentityPublic>,
) -> Result<()> {
    let mut payload = build_filesystem_route_overlay_base(
        artifact_root,
        assigned_components,
        provider_peer_addrs,
        peer_identities,
    )?;
    augment_route_overlay_payload(
        &mut payload,
        proxy_exports,
        provider_peer_addrs,
        peer_identities,
    )?;
    write_dynamic_route_overlay_payload(artifact_root, &payload)
}

pub(super) fn ensure_dynamic_proxy_export_component_routes(
    mesh_plan: &mut MeshProvisionPlan,
    proxy_exports: &BTreeMap<String, DynamicProxyExportRecord>,
    router_identity_id: &str,
) -> Result<()> {
    for export in proxy_exports.values() {
        let protocol = dynamic_proxy_export_mesh_protocol(export)?;
        let route_id = component_route_id(&export.component, &export.provide, protocol);
        let component_target = mesh_plan
            .targets
            .iter_mut()
            .find(|target| {
                matches!(target.kind, MeshProvisionTargetKind::Component)
                    && target.config.identity.id == export.component
            })
            .ok_or_else(|| {
                miette::miette!(
                    "dynamic proxy export provider {} is missing from the mesh provision plan",
                    export.component
                )
            })?;
        if !component_target
            .config
            .peers
            .iter()
            .any(|peer| peer.id == router_identity_id)
        {
            component_target
                .config
                .peers
                .push(amber_mesh::MeshPeerTemplate {
                    id: router_identity_id.to_string(),
                });
        }
        if let Some(route) = component_target
            .config
            .inbound
            .iter_mut()
            .find(|route| route.route_id == route_id)
        {
            if !route
                .allowed_issuers
                .iter()
                .any(|issuer| issuer == router_identity_id)
            {
                route.allowed_issuers.push(router_identity_id.to_string());
                route.allowed_issuers.sort();
                route.allowed_issuers.dedup();
            }
            continue;
        }
        component_target.config.inbound.push(InboundRoute {
            route_id,
            capability: export.provide.clone(),
            capability_kind: Some(export.capability_kind.clone()),
            capability_profile: export.capability_profile.clone(),
            protocol,
            http_plugins: dynamic_proxy_export_http_plugins(export, protocol),
            target: InboundTarget::Local {
                port: export.target_port,
            },
            allowed_issuers: vec![router_identity_id.to_string()],
        });
    }
    Ok(())
}

pub(super) fn ensure_dynamic_proxy_export_component_routes_in_artifact(
    artifact_root: &Path,
    proxy_exports: &BTreeMap<String, DynamicProxyExportRecord>,
    router_identity_id: &str,
) -> Result<()> {
    let plan_path = artifact_root.join("mesh-provision-plan.json");
    let mut mesh_plan: MeshProvisionPlan = read_json(&plan_path, "mesh provision plan")?;
    ensure_dynamic_proxy_export_component_routes(
        &mut mesh_plan,
        proxy_exports,
        router_identity_id,
    )?;
    write_json(&plan_path, &mesh_plan)
}

pub(super) fn add_dynamic_proxy_export_overlay_routes(
    inbound_routes: &mut Vec<InboundRoute>,
    proxy_exports: &BTreeMap<String, DynamicProxyExportRecord>,
    mut peer_addr_for_export: impl FnMut(&DynamicProxyExportRecord) -> Result<String>,
) -> Result<()> {
    for (export_name, export) in proxy_exports {
        let protocol = dynamic_proxy_export_mesh_protocol(export)?;
        let route_id = router_dynamic_export_route_id(&export.component, export_name, protocol);
        let route = InboundRoute {
            route_id,
            capability: export_name.clone(),
            capability_kind: Some(export.capability_kind.clone()),
            capability_profile: export.capability_profile.clone(),
            protocol,
            http_plugins: dynamic_proxy_export_http_plugins(export, protocol),
            target: InboundTarget::MeshForward {
                peer_addr: peer_addr_for_export(export)?,
                peer_id: export.component.clone(),
                route_id: component_route_id(&export.component, &export.provide, protocol),
                capability: export.provide.clone(),
            },
            allowed_issuers: Vec::new(),
        };
        if let Some(existing) = inbound_routes
            .iter_mut()
            .find(|existing| existing.route_id == route.route_id)
        {
            *existing = route;
        } else {
            inbound_routes.push(route);
        }
    }
    Ok(())
}

pub(super) struct DynamicComposeMeshPlan {
    pub(super) mesh_plan: MeshProvisionPlan,
    pub(super) mesh_dirs: BTreeMap<String, String>,
    pub(super) component_mesh_dirs: BTreeMap<String, String>,
}

pub(super) fn build_dynamic_compose_mesh_plan(
    artifact_root: &Path,
    assigned_components: &[String],
) -> Result<DynamicComposeMeshPlan> {
    let plan = read_embedded_compose_mesh_provision_plan(artifact_root)?;
    let assigned = assigned_components
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut filtered_targets = Vec::new();
    let mut mesh_dirs = BTreeMap::new();
    let mut component_mesh_dirs = BTreeMap::new();

    for mut target in plan.targets {
        match target.kind {
            MeshProvisionTargetKind::Component => {
                if !assigned.contains(target.config.identity.id.as_str()) {
                    continue;
                }
                let MeshProvisionOutput::Filesystem { dir } = &mut target.output else {
                    return Err(miette::miette!(
                        "compose component {} does not use filesystem mesh output",
                        target.config.identity.id
                    ));
                };
                let sidecar = Path::new(dir.as_str())
                    .file_name()
                    .and_then(|value| value.to_str())
                    .ok_or_else(|| {
                        miette::miette!(
                            "compose component {} has invalid mesh output dir {}",
                            target.config.identity.id,
                            dir
                        )
                    })?
                    .to_string();
                let relative_dir = dynamic_compose_mesh_dir(&sidecar);
                dir.clear();
                dir.push_str(&relative_dir);
                component_mesh_dirs.insert(target.config.identity.id.clone(), relative_dir.clone());
                mesh_dirs.insert(sidecar, relative_dir);
                filtered_targets.push(target);
            }
            MeshProvisionTargetKind::Router => {}
        }
    }

    if filtered_targets.is_empty() {
        return Err(miette::miette!(
            "compose child artifact {} does not contain assigned child mesh targets",
            artifact_root.join("compose.yaml").display()
        ));
    }

    Ok(DynamicComposeMeshPlan {
        mesh_plan: MeshProvisionPlan {
            version: plan.version,
            identity_seed: plan.identity_seed,
            existing_peer_identities: Vec::new(),
            targets: filtered_targets,
        },
        mesh_dirs,
        component_mesh_dirs,
    })
}

pub(super) fn project_dynamic_direct_router_surface(
    plan: &SiteControllerRuntimePlan,
    child: &SiteControllerRuntimeChildRecord,
) -> Result<()> {
    let state_path = direct_runtime_state_path(Path::new(&child.artifact_root));
    let router_mesh_port = plan.router_mesh_port.ok_or_else(|| {
        miette::miette!(
            "direct site `{}` is missing its router mesh port",
            plan.site_id
        )
    })?;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let mut state: DirectRuntimeState = read_json(&state_path, "direct runtime state")?;
        if state.router_mesh_port == Some(router_mesh_port) {
            break;
        }
        state.router_mesh_port = Some(router_mesh_port);
        write_json(&state_path, &state)?;
        std::thread::sleep(Duration::from_millis(100));
        let state: DirectRuntimeState = read_json(&state_path, "direct runtime state")?;
        if state.router_mesh_port == Some(router_mesh_port) {
            break;
        }
        if std::time::Instant::now() >= deadline {
            return Err(miette::miette!(
                "timed out projecting direct child router mesh port into {}",
                state_path.display()
            ));
        }
    }

    let site_current = direct_current_control_socket_path(Path::new(&plan.artifact_dir));
    let child_current = direct_current_control_socket_path(Path::new(&child.artifact_root));
    if let Some(parent) = child_current.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to create {}", parent.display()))?;
    }
    ensure_direct_control_socket_link(
        &child_current,
        &site_current,
        "dynamic child router control symlink",
    )?;
    let artifact_link = Path::new(&child.artifact_root)
        .join(".amber")
        .join("control")
        .join("router-control.sock");
    if let Some(parent) = artifact_link.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to create {}", parent.display()))?;
    }
    ensure_direct_control_socket_link(
        &artifact_link,
        &child_current,
        "dynamic child router control artifact symlink",
    )
}

pub(super) fn project_dynamic_vm_router_surface(
    plan: &SiteControllerRuntimePlan,
    child: &SiteControllerRuntimeChildRecord,
) -> Result<()> {
    let state_path = Path::new(&child.artifact_root)
        .join(".amber")
        .join("vm-runtime.json");
    let runtime_root = site_controller_runtime_child_runtime_root(plan, child.child_id);
    let router_mesh_port = plan.router_mesh_port.ok_or_else(|| {
        miette::miette!("vm site `{}` is missing its router mesh port", plan.site_id)
    })?;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let mut state =
            load_vm_runtime_state_for_artifact(Path::new(&child.artifact_root), &runtime_root)?;
        if state.router_mesh_port == Some(router_mesh_port) {
            break;
        }
        state.router_mesh_port = Some(router_mesh_port);
        write_vm_runtime_state(Path::new(&child.artifact_root), &state)?;
        std::thread::sleep(Duration::from_millis(100));
        let state =
            load_vm_runtime_state_for_artifact(Path::new(&child.artifact_root), &runtime_root)?;
        if state.router_mesh_port == Some(router_mesh_port) {
            break;
        }
        if std::time::Instant::now() >= deadline {
            return Err(miette::miette!(
                "timed out projecting vm child router mesh port into {}",
                state_path.display()
            ));
        }
    }

    let site_current = vm_current_control_socket_path(Path::new(&plan.artifact_dir));
    let child_current = vm_current_control_socket_path(Path::new(&child.artifact_root));
    if let Some(parent) = child_current.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to create {}", parent.display()))?;
    }
    ensure_control_socket_link(
        &child_current,
        &site_current,
        "dynamic child vm router control symlink",
    )?;
    let artifact_link = Path::new(&child.artifact_root)
        .join(".amber")
        .join("control")
        .join("router-control.sock");
    if let Some(parent) = artifact_link.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to create {}", parent.display()))?;
    }
    ensure_control_socket_link(
        &artifact_link,
        &child_current,
        "dynamic child vm router control artifact symlink",
    )
}

pub(super) fn dynamic_child_route_overlay_id(
    plan: &SiteControllerRuntimePlan,
    child_id: u64,
) -> String {
    format!("framework-child:{}:{child_id}", plan.site_id)
}

pub(super) fn site_router_control_endpoint(
    plan: &SiteControllerRuntimePlan,
) -> Result<ControlEndpoint> {
    if plan.kind == SiteKind::Kubernetes
        && let Some(raw) = plan.local_router_control.as_deref()
    {
        return parse_control_endpoint(raw);
    }
    let state_path = Path::new(&plan.site_state_root).join("manager-state.json");
    if state_path.is_file() {
        let state: SiteManagerState = read_json(&state_path, "site manager state")?;
        if let Some(raw) = state.router_control {
            return parse_control_endpoint(&raw);
        }
    }

    match plan.kind {
        SiteKind::Direct => Ok(ControlEndpoint::Unix(direct_current_control_socket_path(
            Path::new(&plan.artifact_dir),
        ))),
        SiteKind::Vm => Ok(ControlEndpoint::Unix(vm_current_control_socket_path(
            Path::new(&plan.artifact_dir),
        ))),
        SiteKind::Compose | SiteKind::Kubernetes => Err(miette::miette!(
            "site `{}` manager state is missing router control endpoint",
            plan.site_id
        )),
    }
}

async fn site_router_overlay_control_endpoint_with_timeout(
    plan: &SiteControllerRuntimePlan,
    timeout: Duration,
) -> Result<ControlEndpoint> {
    if plan.kind == SiteKind::Kubernetes {
        wait_for_kubernetes_site_router_ready(plan, timeout).await?;
    }
    site_router_control_endpoint(plan)
}

async fn site_router_overlay_control_endpoint(
    plan: &SiteControllerRuntimePlan,
) -> Result<ControlEndpoint> {
    site_router_overlay_control_endpoint_with_timeout(plan, site_ready_timeout_for_kind(plan.kind))
        .await
}

pub(super) fn child_router_overlay_payload(
    plan: &SiteControllerRuntimePlan,
    artifact_root: &Path,
    runtime_root: &Path,
) -> Result<(Vec<MeshPeer>, Vec<InboundRoute>)> {
    let overlay_path = dynamic_route_overlay_path(artifact_root);
    if overlay_path.is_file() {
        let payload: StoredRouteOverlayPayload = read_json(&overlay_path, "site router overlay")?;
        return Ok((payload.peers, payload.inbound_routes));
    }
    let provision: MeshProvisionPlan = read_json(
        &artifact_root.join("mesh-provision-plan.json"),
        "mesh provision plan",
    )?;
    let Some(router_target) = provision
        .targets
        .iter()
        .find(|target| matches!(target.kind, MeshProvisionTargetKind::Router))
    else {
        return Ok((Vec::new(), Vec::new()));
    };
    let proxy_exports = load_dynamic_proxy_exports_metadata(artifact_root)?;
    let mut overlay_peer_ids = router_target
        .config
        .peers
        .iter()
        .map(|peer| peer.id.clone())
        .collect::<BTreeSet<_>>();
    overlay_peer_ids.extend(
        proxy_exports
            .values()
            .map(|export| export.component.clone()),
    );

    let mut peers = Vec::new();
    let mut peer_addr_by_id = BTreeMap::new();
    for peer_id in &overlay_peer_ids {
        let component_target = provision
            .targets
            .iter()
            .find(|target| {
                matches!(target.kind, MeshProvisionTargetKind::Component)
                    && target.config.identity.id == *peer_id
            })
            .ok_or_else(|| {
                miette::miette!(
                    "router overlay peer {} is missing from mesh provision plan",
                    peer_id
                )
            })?;
        let (identity, runtime_config) = match &component_target.output {
            MeshProvisionOutput::Filesystem { dir } => {
                let identity: MeshIdentitySecret = read_json(
                    &runtime_root.join(dir).join(MESH_IDENTITY_FILENAME),
                    "mesh identity",
                )?;
                let runtime_config: MeshConfigPublic = read_json(
                    &runtime_root.join(dir).join(MESH_CONFIG_FILENAME),
                    "mesh config",
                )?;
                (identity, Some(runtime_config))
            }
            MeshProvisionOutput::KubernetesSecret { name, namespace } => (
                load_kubernetes_mesh_identity_secret(plan, name, namespace.as_deref())?,
                None,
            ),
        };
        let public_key = identity.public_key().into_diagnostic()?;
        if let Some(runtime_config) = runtime_config {
            peer_addr_by_id.insert(
                runtime_config.identity.id.clone(),
                runtime_config.mesh_listen.to_string(),
            );
        }
        peers.push(MeshPeer {
            id: identity.id,
            public_key,
        });
    }
    let mut inbound_routes = router_target.config.inbound.clone();
    for route in &mut inbound_routes {
        if let InboundTarget::MeshForward {
            peer_id, peer_addr, ..
        } = &mut route.target
            && let Some(resolved) = peer_addr_by_id.get(peer_id)
        {
            peer_addr.clone_from(resolved);
        }
    }
    if !proxy_exports.is_empty() {
        add_dynamic_proxy_export_overlay_routes(&mut inbound_routes, &proxy_exports, |export| {
            match plan.kind {
                SiteKind::Kubernetes => {
                    dynamic_proxy_export_kubernetes_peer_addr(artifact_root, &provision, export)
                }
                SiteKind::Direct | SiteKind::Vm | SiteKind::Compose => peer_addr_by_id
                    .get(&export.component)
                    .map(ToString::to_string)
                    .ok_or_else(|| {
                        miette::miette!(
                            "dynamic proxy export provider {} is missing a live mesh address",
                            export.component
                        )
                    }),
            }
        })?;
    }
    Ok((peers, inbound_routes))
}

pub(super) fn child_overlay_runtime_root(
    plan: &SiteControllerRuntimePlan,
    child: &SiteControllerRuntimeChildRecord,
) -> PathBuf {
    match plan.kind {
        SiteKind::Direct | SiteKind::Vm => {
            site_controller_runtime_child_runtime_root(plan, child.child_id)
        }
        SiteKind::Compose | SiteKind::Kubernetes => PathBuf::from(&child.artifact_root),
    }
}

pub(super) const SITE_CONTROLLER_INTERNAL_OVERLAY_ID: &str = "framework-site-controller";

fn local_site_controller_runtime(
    live_components: &BTreeMap<String, LiveComponentRuntimeMetadata>,
) -> Result<Option<&LiveComponentRuntimeMetadata>> {
    let mut controllers = live_components.values().filter(|runtime| {
        runtime.mesh_config.inbound.iter().any(|route| {
            route.capability == amber_mesh::FRAMEWORK_COMPONENT_CONTROLLER_INTERNAL_PROVIDE_NAME
        })
    });
    let Some(controller) = controllers.next() else {
        return Ok(None);
    };
    if controllers.next().is_some() {
        return Err(miette::miette!(
            "dynamic site controller overlay found multiple local framework.component controller \
             runtimes"
        ));
    }
    Ok(Some(controller))
}

fn dynamic_site_controller_overlay_payload(
    published_children: &[SiteControllerRuntimeChildRecord],
    live_components: &BTreeMap<String, LiveComponentRuntimeMetadata>,
) -> Result<Option<StoredRouteOverlayPayload>> {
    let Some(controller_runtime) = local_site_controller_runtime(live_components)? else {
        return Ok(None);
    };

    let mut routes_by_id = BTreeMap::<String, InboundRoute>::new();
    let mut issuer_ids = BTreeSet::<String>::new();
    for child in published_children {
        for route in &child.controller_routes {
            if route.allowed_issuers.is_empty() {
                continue;
            }
            issuer_ids.extend(route.allowed_issuers.iter().cloned());
            if let Some(existing) = routes_by_id.get_mut(&route.route_id) {
                if !controller_overlay_routes_compatible(existing, route) {
                    return Err(miette::miette!(
                        "dynamic controller overlay route {} is defined with incompatible route \
                         metadata",
                        route.route_id
                    ));
                }
                existing
                    .allowed_issuers
                    .extend(route.allowed_issuers.iter().cloned());
                existing.allowed_issuers.sort();
                existing.allowed_issuers.dedup();
            } else {
                let mut route = route.clone();
                route.allowed_issuers.sort();
                route.allowed_issuers.dedup();
                routes_by_id.insert(route.route_id.clone(), route);
            }
        }
    }
    if routes_by_id.is_empty() {
        return Ok(None);
    }

    let static_peer_ids = controller_runtime
        .mesh_config
        .peers
        .iter()
        .map(|peer| peer.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut peers = Vec::new();
    for issuer_id in issuer_ids {
        if issuer_id == controller_runtime.mesh_config.identity.id
            || static_peer_ids.contains(issuer_id.as_str())
        {
            continue;
        }
        let runtime = live_components.get(&issuer_id).ok_or_else(|| {
            miette::miette!(
                "dynamic controller overlay route grants issuer {} but that peer is not live on \
                 site {}",
                issuer_id,
                controller_runtime.moniker
            )
        })?;
        peers.push(MeshPeer {
            id: runtime.mesh_config.identity.id.clone(),
            public_key: runtime.mesh_config.identity.public_key,
        });
    }

    Ok(Some(StoredRouteOverlayPayload {
        peers,
        inbound_routes: routes_by_id.into_values().collect(),
    }))
}

fn dynamic_site_controller_overlay_required(
    published_children: &[SiteControllerRuntimeChildRecord],
) -> bool {
    published_children.iter().any(|child| {
        child
            .controller_routes
            .iter()
            .any(|route| !route.allowed_issuers.is_empty())
    })
}

fn controller_overlay_routes_compatible(left: &InboundRoute, right: &InboundRoute) -> bool {
    left.capability == right.capability
        && left.capability_kind == right.capability_kind
        && left.capability_profile == right.capability_profile
        && left.protocol == right.protocol
        && left.http_plugins == right.http_plugins
        && left.target == right.target
}

pub(super) fn dynamic_direct_input_overlay_id(component: &str) -> String {
    format!(
        "framework-direct-inputs:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(component.as_bytes())
    )
}

pub(super) fn dynamic_direct_input_grants(
    children: &[SiteControllerRuntimeChildRecord],
) -> Result<BTreeMap<String, BTreeMap<String, BTreeSet<String>>>> {
    let mut grants = BTreeMap::<String, BTreeMap<String, BTreeSet<String>>>::new();
    for child in children {
        for input in &child.direct_inputs {
            let route_id =
                dynamic_input_direct_route_id(input, dynamic_input_direct_mesh_protocol(input)?);
            grants
                .entry(input.provider_component.clone())
                .or_default()
                .entry(route_id)
                .or_default()
                .insert(input.component.clone());
        }
    }
    Ok(grants)
}

pub(super) async fn reconcile_dynamic_site_controller_overlay(
    app: &SiteControllerRuntimeApp,
) -> Result<()> {
    let published_children = {
        let state = app.state.lock().await;
        state
            .children
            .values()
            .filter(|child| child.published)
            .cloned()
            .collect::<Vec<_>>()
    };
    let live_components = collect_live_component_runtime_metadata(&app.plan)?;
    let Some(controller_runtime) = local_site_controller_runtime(&live_components)? else {
        if !dynamic_site_controller_overlay_required(&published_children) {
            return Ok(());
        }
        return Err(miette::miette!(
            "site {} has published dynamic children but no live framework.component controller \
             component",
            app.plan.site_id
        ));
    };
    let Some(control_endpoint) = controller_runtime.control_endpoint.as_ref() else {
        return Ok(());
    };
    let Some(overlay) =
        dynamic_site_controller_overlay_payload(&published_children, &live_components)?
    else {
        revoke_route_overlay_with_retry(
            control_endpoint,
            SITE_CONTROLLER_INTERNAL_OVERLAY_ID,
            Duration::from_secs(30),
        )
        .await?;
        return Ok(());
    };
    apply_route_overlay_with_retry(
        control_endpoint,
        SITE_CONTROLLER_INTERNAL_OVERLAY_ID,
        &overlay.peers,
        &overlay.inbound_routes,
        Duration::from_secs(30),
    )
    .await
}

pub(super) async fn reconcile_dynamic_direct_input_overlays(
    app: &SiteControllerRuntimeApp,
) -> Result<()> {
    let (published_children, previous_overlay_providers) = {
        let state = app.state.lock().await;
        (
            state
                .children
                .values()
                .filter(|child| child.published)
                .cloned()
                .collect::<Vec<_>>(),
            state.direct_input_overlay_providers.clone(),
        )
    };
    let live_components = collect_live_component_runtime_metadata(&app.plan)?;
    let grants = dynamic_direct_input_grants(&published_children)?;
    let current_overlay_providers = grants.keys().cloned().collect::<BTreeSet<_>>();
    let overlay_providers = current_overlay_providers
        .union(&previous_overlay_providers)
        .cloned()
        .collect::<BTreeSet<_>>();
    for component in &overlay_providers {
        let Some(runtime) = live_components.get(component) else {
            continue;
        };
        let Some(control_endpoint) = runtime.control_endpoint.as_ref() else {
            continue;
        };
        let overlay_id = dynamic_direct_input_overlay_id(component);
        let Some(route_grants) = grants.get(component) else {
            revoke_route_overlay_with_retry(control_endpoint, &overlay_id, Duration::from_secs(30))
                .await?;
            continue;
        };

        let mut peers = Vec::new();
        let mut known_peer_ids = BTreeSet::new();
        let mut inbound_routes = Vec::new();
        for (route_id, issuers) in route_grants {
            let base_route = runtime
                .mesh_config
                .inbound
                .iter()
                .find(|route| route.route_id == *route_id)
                .cloned()
                .ok_or_else(|| {
                    miette::miette!(
                        "provider component {} is missing inbound route {} for a direct dynamic \
                         input",
                        component,
                        route_id
                    )
                })?;
            let mut route = base_route;
            route.allowed_issuers = issuers.iter().cloned().collect();
            for issuer in issuers {
                let issuer_runtime = live_components.get(issuer).ok_or_else(|| {
                    miette::miette!(
                        "direct dynamic input issuer {} is not live on site {}",
                        issuer,
                        app.plan.site_id
                    )
                })?;
                if known_peer_ids.insert(issuer_runtime.mesh_config.identity.id.clone()) {
                    peers.push(MeshPeer {
                        id: issuer_runtime.mesh_config.identity.id.clone(),
                        public_key: issuer_runtime.mesh_config.identity.public_key,
                    });
                }
            }
            inbound_routes.push(route);
        }
        apply_route_overlay_with_retry(
            control_endpoint,
            &overlay_id,
            &peers,
            &inbound_routes,
            Duration::from_secs(30),
        )
        .await?;
    }
    let mut state = app.state.lock().await;
    if state.direct_input_overlay_providers != current_overlay_providers {
        state.direct_input_overlay_providers = current_overlay_providers;
        write_json(&app.state_path, &*state)?;
    }
    Ok(())
}

pub(super) async fn reconcile_dynamic_site_router_overlays(
    app: &SiteControllerRuntimeApp,
) -> Result<()> {
    let published_children = {
        let state = app.state.lock().await;
        state
            .children
            .values()
            .filter(|child| child.published)
            .cloned()
            .collect::<Vec<_>>()
    };
    reconcile_dynamic_site_router_overlays_for_children(
        app,
        &published_children,
        &published_children,
    )
    .await
}

pub(super) async fn reconcile_dynamic_site_router_overlays_for_children(
    app: &SiteControllerRuntimeApp,
    overlay_children: &[SiteControllerRuntimeChildRecord],
    issuer_children: &[SiteControllerRuntimeChildRecord],
) -> Result<()> {
    if overlay_children.is_empty() {
        return Ok(());
    }
    let endpoint = site_router_overlay_control_endpoint(&app.plan).await?;
    let _ = issuer_children;
    for child in overlay_children {
        let artifact_root = Path::new(&child.artifact_root);
        let runtime_root = child_overlay_runtime_root(&app.plan, child);
        let (peers, inbound_routes) =
            child_router_overlay_payload(&app.plan, artifact_root, &runtime_root)?;
        if inbound_routes.is_empty() {
            continue;
        }
        apply_route_overlay_with_retry(
            &endpoint,
            &dynamic_child_route_overlay_id(&app.plan, child.child_id),
            &peers,
            &inbound_routes,
            Duration::from_secs(30),
        )
        .await?;
    }

    Ok(())
}

pub(super) async fn apply_dynamic_site_router_overlay(
    plan: &SiteControllerRuntimePlan,
    child: &SiteControllerRuntimeChildRecord,
) -> Result<()> {
    let endpoint = site_router_overlay_control_endpoint(plan).await?;
    let artifact_root = Path::new(&child.artifact_root);
    let runtime_root = child_overlay_runtime_root(plan, child);
    let (peers, inbound_routes) = child_router_overlay_payload(plan, artifact_root, &runtime_root)?;
    if inbound_routes.is_empty() {
        return Ok(());
    }
    apply_route_overlay_with_retry(
        &endpoint,
        &dynamic_child_route_overlay_id(plan, child.child_id),
        &peers,
        &inbound_routes,
        Duration::from_secs(30),
    )
    .await
}

pub(super) async fn revoke_dynamic_site_router_overlay(
    plan: &SiteControllerRuntimePlan,
    child: &SiteControllerRuntimeChildRecord,
) -> Result<()> {
    let endpoint = site_router_overlay_control_endpoint(plan).await?;
    revoke_route_overlay_with_retry(
        &endpoint,
        &dynamic_child_route_overlay_id(plan, child.child_id),
        Duration::from_secs(30),
    )
    .await
}

#[cfg(test)]
mod direct_input_tests {
    use std::{
        fs,
        net::SocketAddr,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::{Duration as StdDuration, Instant as StdInstant},
    };

    use amber_mesh::MeshConfigTemplate;
    use axum::response::IntoResponse;

    use super::*;

    async fn spawn_mock_router_mesh_listener() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("mock router mesh listener should bind");
        let addr = listener
            .local_addr()
            .expect("mock router mesh listener addr should resolve");
        let handle = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        });
        (addr, handle)
    }

    async fn spawn_gated_router_control_listener(
        ready: Arc<AtomicBool>,
        saw_mutation: Arc<AtomicBool>,
        mutated_before_ready: Arc<AtomicBool>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("mock router control listener should bind");
        let addr = listener
            .local_addr()
            .expect("mock router control listener addr should resolve");
        let router = axum::Router::new()
            .route(
                "/identity",
                axum::routing::get({
                    let ready = ready.clone();
                    move || {
                        let ready = ready.clone();
                        async move {
                            if ready.load(Ordering::SeqCst) {
                                axum::Json(MeshIdentityPublic {
                                    id: "/site/kind_local/router".to_string(),
                                    public_key: [9u8; 32],
                                    mesh_scope: Some("test-mesh".to_string()),
                                })
                                .into_response()
                            } else {
                                axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response()
                            }
                        }
                    }
                }),
            )
            .route(
                "/overlays/{overlay_id}",
                axum::routing::put({
                    let ready = ready.clone();
                    let saw_mutation = saw_mutation.clone();
                    let mutated_before_ready = mutated_before_ready.clone();
                    move || {
                        let ready = ready.clone();
                        let saw_mutation = saw_mutation.clone();
                        let mutated_before_ready = mutated_before_ready.clone();
                        async move {
                            saw_mutation.store(true, Ordering::SeqCst);
                            if !ready.load(Ordering::SeqCst) {
                                mutated_before_ready.store(true, Ordering::SeqCst);
                            }
                            axum::http::StatusCode::NO_CONTENT
                        }
                    }
                })
                .delete({
                    let ready = ready.clone();
                    let saw_mutation = saw_mutation.clone();
                    let mutated_before_ready = mutated_before_ready.clone();
                    move || {
                        let ready = ready.clone();
                        let saw_mutation = saw_mutation.clone();
                        let mutated_before_ready = mutated_before_ready.clone();
                        async move {
                            saw_mutation.store(true, Ordering::SeqCst);
                            if !ready.load(Ordering::SeqCst) {
                                mutated_before_ready.store(true, Ordering::SeqCst);
                            }
                            axum::http::StatusCode::NO_CONTENT
                        }
                    }
                }),
            );
        let handle = tokio::spawn(async move {
            axum::serve(listener, router.into_make_service())
                .await
                .expect("mock router control server should run");
        });
        (addr, handle)
    }

    fn kubernetes_overlay_test_plan(
        temp: &tempfile::TempDir,
        control_addr: SocketAddr,
        mesh_addr: SocketAddr,
    ) -> SiteControllerRuntimePlan {
        let artifact_dir = temp.path().join("artifact");
        let site_state_root = temp.path().join("state").join("kind_local");
        fs::create_dir_all(&artifact_dir).expect("artifact dir should exist");
        fs::create_dir_all(&site_state_root).expect("site state root should exist");
        SiteControllerRuntimePlan {
            schema: "amber.run.site_controller_runtime_plan".to_string(),
            version: 1,
            run_id: "test-run".to_string(),
            mesh_scope: "test-mesh".to_string(),
            run_root: temp.path().display().to_string(),
            site_id: "kind_local".to_string(),
            kind: SiteKind::Kubernetes,
            router_identity_id: "/site/kind_local/router".to_string(),
            local_router_control: Some(control_addr.to_string()),
            artifact_dir: artifact_dir.display().to_string(),
            site_state_root: site_state_root.display().to_string(),
            listen_addr: "127.0.0.1:32000".parse().expect("listen addr"),
            storage_root: None,
            runtime_root: None,
            router_mesh_port: Some(mesh_addr.port()),
            compose_project: None,
            kubernetes_namespace: Some("amber-test-kind-local".to_string()),
            context: None,
            observability_endpoint: None,
            vm_endpoint_forward_ready_timeout_secs: None,
            launch_env: BTreeMap::new(),
        }
    }

    #[test]
    fn compose_site_router_control_endpoint_prefers_manager_state_volume_socket() {
        let temp = tempfile::tempdir().expect("tempdir should create");
        let site_state_root = temp.path().join("state").join("compose_local");
        fs::create_dir_all(&site_state_root).expect("site state root should exist");
        write_json(
            &site_state_root.join("manager-state.json"),
            &serde_json::json!({
                "schema": "amber.run.site_manager_state",
                "version": 1,
                "run_id": "test-run",
                "site_id": "compose_local",
                "kind": "compose",
                "status": "running",
                "artifact_dir": temp.path().join("artifact").display().to_string(),
                "supervisor_pid": 1u32,
                "router_control": "volume://demo_amber-router-control/router-control.sock",
                "router_mesh_addr": "127.0.0.1:24000",
            }),
        )
        .expect("manager state should write");
        let plan = SiteControllerRuntimePlan {
            schema: "amber.run.site_controller_runtime_plan".to_string(),
            version: 1,
            run_id: "test-run".to_string(),
            mesh_scope: "test-mesh".to_string(),
            run_root: temp.path().display().to_string(),
            site_id: "compose_local".to_string(),
            kind: SiteKind::Compose,
            router_identity_id: "/site/compose_local/router".to_string(),
            local_router_control: Some("unix:///amber/control/router-control.sock".to_string()),
            artifact_dir: temp.path().join("artifact").display().to_string(),
            site_state_root: site_state_root.display().to_string(),
            listen_addr: "127.0.0.1:32000".parse().expect("listen addr"),
            storage_root: None,
            runtime_root: None,
            router_mesh_port: Some(24000),
            compose_project: Some("demo".to_string()),
            kubernetes_namespace: None,
            context: None,
            observability_endpoint: None,
            vm_endpoint_forward_ready_timeout_secs: None,
            launch_env: BTreeMap::new(),
        };

        assert!(matches!(
            site_router_control_endpoint(&plan).expect("router control endpoint should resolve"),
            ControlEndpoint::VolumeSocket { volume, socket_path }
                if volume == "demo_amber-router-control" && socket_path == "/router-control.sock"
        ));
    }

    #[test]
    fn site_router_control_endpoint_prefers_local_embedded_target_over_manager_state() {
        let temp = tempfile::tempdir().expect("tempdir should create");
        let site_state_root = temp.path().join("state").join("kind_local");
        fs::create_dir_all(&site_state_root).expect("site state root should exist");
        write_json(
            &site_state_root.join("manager-state.json"),
            &serde_json::json!({
                "schema": "amber.run.site_manager_state",
                "version": 1,
                "run_id": "test-run",
                "site_id": "kind_local",
                "kind": "kubernetes",
                "status": "running",
                "artifact_dir": temp.path().join("artifact").display().to_string(),
                "supervisor_pid": 1u32,
                "router_control": "127.0.0.1:9",
                "router_mesh_addr": "127.0.0.1:9",
            }),
        )
        .expect("manager state should write");
        let plan = SiteControllerRuntimePlan {
            schema: "amber.run.site_controller_runtime_plan".to_string(),
            version: 1,
            run_id: "test-run".to_string(),
            mesh_scope: "test-mesh".to_string(),
            run_root: temp.path().display().to_string(),
            site_id: "kind_local".to_string(),
            kind: SiteKind::Kubernetes,
            router_identity_id: "/site/kind_local/router".to_string(),
            local_router_control: Some("amber-router:24100".to_string()),
            artifact_dir: temp.path().join("artifact").display().to_string(),
            site_state_root: site_state_root.display().to_string(),
            listen_addr: "127.0.0.1:32000".parse().expect("listen addr"),
            storage_root: None,
            runtime_root: None,
            router_mesh_port: Some(24000),
            compose_project: None,
            kubernetes_namespace: Some("amber-test-kind-local".to_string()),
            context: None,
            observability_endpoint: None,
            vm_endpoint_forward_ready_timeout_secs: None,
            launch_env: BTreeMap::new(),
        };

        assert!(matches!(
            site_router_control_endpoint(&plan).expect("router control endpoint should resolve"),
            ControlEndpoint::Tcp(addr) if addr == "amber-router:24100"
        ));
    }

    #[tokio::test]
    async fn probe_kubernetes_router_control_ready_accepts_mock_identity_response() {
        let ready = Arc::new(AtomicBool::new(true));
        let (control_addr, control_handle) = spawn_gated_router_control_listener(
            ready,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .await;

        assert!(
            probe_kubernetes_router_control_ready(
                &control_addr.to_string(),
                StdDuration::from_secs(1)
            )
            .await
            .expect("router control probe should succeed"),
            "the mock router control server should satisfy the readiness probe",
        );
        control_handle.abort();
    }

    #[tokio::test]
    async fn router_mesh_listener_ready_target_accepts_mock_listener() {
        let (mesh_addr, mesh_handle) = spawn_mock_router_mesh_listener().await;
        assert!(
            router_mesh_listener_ready_target(&mesh_addr.to_string(), StdDuration::from_secs(1))
                .await,
            "the mock mesh listener should satisfy the mesh readiness probe",
        );
        mesh_handle.abort();
    }

    #[tokio::test]
    async fn site_router_overlay_control_endpoint_waits_for_kubernetes_router_readiness() {
        let temp = tempfile::tempdir().expect("tempdir should create");
        let ready = Arc::new(AtomicBool::new(false));
        let saw_mutation = Arc::new(AtomicBool::new(false));
        let mutated_before_ready = Arc::new(AtomicBool::new(false));
        let (mesh_addr, mesh_handle) = spawn_mock_router_mesh_listener().await;
        let (control_addr, control_handle) =
            spawn_gated_router_control_listener(ready.clone(), saw_mutation, mutated_before_ready)
                .await;
        let plan = kubernetes_overlay_test_plan(&temp, control_addr, mesh_addr);

        let gate = ready.clone();
        let gate_handle = tokio::spawn(async move {
            tokio::time::sleep(StdDuration::from_millis(350)).await;
            gate.store(true, Ordering::SeqCst);
        });

        let start = StdInstant::now();
        let endpoint =
            site_router_overlay_control_endpoint_with_timeout(&plan, StdDuration::from_secs(6))
                .await
                .expect("overlay endpoint should wait for router readiness and then resolve");

        assert!(
            start.elapsed() >= StdDuration::from_millis(300),
            "overlay endpoint resolution should wait until the Kubernetes router is ready",
        );
        assert!(matches!(
            endpoint,
            ControlEndpoint::Tcp(addr) if addr == control_addr.to_string()
        ));
        gate_handle.abort();
        control_handle.abort();
        mesh_handle.abort();
    }

    #[test]
    fn rewrite_dynamic_direct_inputs_points_child_at_provider_sidecar() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("mesh-provision-plan.json");
        write_json(
            &path,
            &MeshProvisionPlan {
                version: amber_mesh::MESH_PROVISION_PLAN_VERSION.to_string(),
                identity_seed: None,
                existing_peer_identities: Vec::new(),
                targets: vec![MeshProvisionTarget {
                    kind: MeshProvisionTargetKind::Component,
                    config: MeshConfigTemplate {
                        identity: amber_mesh::MeshIdentityTemplate {
                            id: "/consumer".to_string(),
                            mesh_scope: None,
                        },
                        mesh_listen: "127.0.0.1:0".parse().expect("mesh listen"),
                        control_listen: None,
                        dynamic_caps_listen: None,
                        control_allow: None,
                        peers: Vec::new(),
                        inbound: Vec::new(),
                        outbound: vec![OutboundRoute {
                            route_id: "old".to_string(),
                            rewrite_route_id: None,
                            slot: "api".to_string(),
                            capability_kind: Some("http".to_string()),
                            capability_profile: None,
                            listen_port: 0,
                            listen_addr: None,
                            protocol: MeshProtocol::Http,
                            http_plugins: Vec::new(),
                            peer_addr: "127.0.0.1:1".to_string(),
                            peer_id: "/router".to_string(),
                            capability: "old".to_string(),
                        }],
                        transport: amber_mesh::TransportConfig::NoiseIk {},
                    },
                    output: MeshProvisionOutput::Filesystem {
                        dir: "mesh/components/consumer".to_string(),
                    },
                }],
            },
        )
        .expect("write mesh plan");

        let mut live_components = BTreeMap::new();
        live_components.insert(
            "/provider".to_string(),
            LiveComponentRuntimeMetadata {
                moniker: "/provider".to_string(),
                router_reachable_mesh_addr: "127.0.0.1:24001".to_string(),
                component_reachable_mesh_addr: "10.0.0.20:24001".to_string(),
                control_endpoint: None,
                mesh_config: MeshConfigPublic {
                    identity: MeshIdentityPublic {
                        id: "/provider".to_string(),
                        public_key: [7; 32],
                        mesh_scope: None,
                    },
                    mesh_listen: "127.0.0.1:0".parse().expect("mesh listen"),
                    control_listen: None,
                    dynamic_caps_listen: None,
                    control_allow: None,
                    peers: Vec::new(),
                    inbound: Vec::new(),
                    outbound: Vec::new(),
                    transport: amber_mesh::TransportConfig::NoiseIk {},
                },
            },
        );
        rewrite_dynamic_direct_inputs_in_artifact(
            temp.path(),
            &[DynamicInputDirectRecord {
                component: "/consumer".to_string(),
                slot: "api".to_string(),
                provider_component: "/provider".to_string(),
                protocol: "http".to_string(),
                capability_kind: "http".to_string(),
                capability_profile: None,
                target: DynamicInputRouteTarget::ComponentProvide {
                    provide: "serve".to_string(),
                },
            }],
            &live_components,
        )
        .expect("rewrite should succeed");

        let plan: MeshProvisionPlan = read_json(&path, "mesh provision plan").expect("plan");
        let target = &plan.targets[0];
        assert_eq!(target.config.peers.len(), 1);
        assert_eq!(target.config.peers[0].id, "/provider");
        let route = &target.config.outbound[0];
        assert_eq!(route.peer_id, "/provider");
        assert_eq!(route.peer_addr, "10.0.0.20:24001");
        assert_eq!(route.capability, "serve");
        assert_eq!(
            route.route_id,
            component_route_id("/provider", "serve", MeshProtocol::Http)
        );
    }

    #[test]
    fn dynamic_direct_input_overlay_id_is_path_safe_for_component_monikers() {
        let overlay_id = dynamic_direct_input_overlay_id("/source");
        assert_eq!(
            overlay_id, "framework-direct-inputs:L3NvdXJjZQ",
            "overlay ids should encode component monikers so router control paths stay \
             single-segment",
        );
        assert!(
            !overlay_id.contains('/'),
            "overlay ids must not contain path separators: {overlay_id}",
        );
    }

    #[test]
    fn dynamic_direct_input_overlay_targets_only_current_and_previous_providers() {
        let current = BTreeSet::from(["/provider".to_string()]);
        let previous = BTreeSet::from(["/provider".to_string(), "/stale".to_string()]);

        let overlay_providers = current.union(&previous).cloned().collect::<BTreeSet<_>>();

        assert_eq!(
            overlay_providers,
            BTreeSet::from(["/provider".to_string(), "/stale".to_string()]),
            "reconciliation should only touch providers with current grants or previously applied \
             overlays",
        );
    }

    #[test]
    fn dynamic_site_controller_overlay_uses_child_controller_route_grants() {
        let internal_route_id = component_route_id(
            "/__amber_internal_framework_component_controller/site-a",
            amber_mesh::FRAMEWORK_COMPONENT_CONTROLLER_INTERNAL_PROVIDE_NAME,
            MeshProtocol::Http,
        );
        let grant_route_id = component_route_id(
            "/__amber_internal_framework_component_controller/site-a",
            "__amber_internal_framework_component__site_site-a__authority_root",
            MeshProtocol::Http,
        );
        let live_components = BTreeMap::from([
            (
                "/__amber_internal_framework_component_controller/site-a".to_string(),
                LiveComponentRuntimeMetadata {
                    moniker: "/__amber_internal_framework_component_controller/site-a".to_string(),
                    router_reachable_mesh_addr: "127.0.0.1:24000".to_string(),
                    component_reachable_mesh_addr: "127.0.0.1:24000".to_string(),
                    control_endpoint: Some(ControlEndpoint::Unix("/tmp/controller.sock".into())),
                    mesh_config: MeshConfigPublic {
                        identity: MeshIdentityPublic {
                            id: "/__amber_internal_framework_component_controller/site-a"
                                .to_string(),
                            public_key: [1; 32],
                            mesh_scope: None,
                        },
                        mesh_listen: "127.0.0.1:23000".parse().expect("mesh listen"),
                        control_listen: None,
                        dynamic_caps_listen: None,
                        control_allow: None,
                        peers: vec![MeshPeer {
                            id: "/static".to_string(),
                            public_key: [2; 32],
                        }],
                        inbound: vec![InboundRoute {
                            route_id: internal_route_id.clone(),
                            capability:
                                amber_mesh::FRAMEWORK_COMPONENT_CONTROLLER_INTERNAL_PROVIDE_NAME
                                    .to_string(),
                            capability_kind: None,
                            capability_profile: None,
                            protocol: MeshProtocol::Http,
                            http_plugins: Vec::new(),
                            target: InboundTarget::Local { port: 8080 },
                            allowed_issuers: vec![
                                "/site/router".to_string(),
                                "/static".to_string(),
                            ],
                        }],
                        outbound: Vec::new(),
                        transport: amber_mesh::TransportConfig::NoiseIk {},
                    },
                },
            ),
            (
                "/job-dynamic".to_string(),
                LiveComponentRuntimeMetadata {
                    moniker: "/job-dynamic".to_string(),
                    router_reachable_mesh_addr: "127.0.0.1:24001".to_string(),
                    component_reachable_mesh_addr: "127.0.0.1:24001".to_string(),
                    control_endpoint: Some(ControlEndpoint::Unix("/tmp/job.sock".into())),
                    mesh_config: MeshConfigPublic {
                        identity: MeshIdentityPublic {
                            id: "/job-dynamic".to_string(),
                            public_key: [3; 32],
                            mesh_scope: None,
                        },
                        mesh_listen: "127.0.0.1:23001".parse().expect("mesh listen"),
                        control_listen: None,
                        dynamic_caps_listen: Some(
                            "127.0.0.1:19001".parse().expect("dynamic caps listen"),
                        ),
                        control_allow: None,
                        peers: Vec::new(),
                        inbound: Vec::new(),
                        outbound: Vec::new(),
                        transport: amber_mesh::TransportConfig::NoiseIk {},
                    },
                },
            ),
        ]);

        let overlay = dynamic_site_controller_overlay_payload(
            &[SiteControllerRuntimeChildRecord {
                child_id: 7,
                artifact_root: "/tmp/child".to_string(),
                assigned_components: vec!["/job-dynamic".to_string()],
                controller_routes: vec![InboundRoute {
                    route_id: grant_route_id.clone(),
                    capability: "__amber_internal_framework_component__site_site-a__authority_root"
                        .to_string(),
                    capability_kind: Some("framework.component".to_string()),
                    capability_profile: None,
                    protocol: MeshProtocol::Http,
                    http_plugins: Vec::new(),
                    target: InboundTarget::Local { port: 8080 },
                    allowed_issuers: vec!["/job-dynamic".to_string()],
                }],
                proxy_exports: BTreeMap::new(),
                direct_inputs: Vec::new(),
                process_pid: None,
                published: true,
            }],
            &live_components,
        )
        .expect("overlay payload should build")
        .expect("dynamic child should require an overlay");

        assert_eq!(overlay.peers.len(), 1);
        assert_eq!(overlay.peers[0].id, "/job-dynamic");
        assert_eq!(overlay.peers[0].public_key, [3; 32]);
        assert_eq!(overlay.inbound_routes.len(), 1);
        assert_eq!(overlay.inbound_routes[0].route_id, grant_route_id);
        assert_eq!(
            overlay.inbound_routes[0].allowed_issuers,
            vec!["/job-dynamic".to_string()],
            "the overlay should contribute only the dynamic child issuer recorded for this \
             grant-specific controller route",
        );
    }

    #[test]
    fn dynamic_site_controller_overlay_is_required_only_for_granted_controller_routes() {
        let child = |controller_routes| SiteControllerRuntimeChildRecord {
            child_id: 7,
            artifact_root: "/tmp/child".to_string(),
            assigned_components: vec!["/job-dynamic".to_string()],
            controller_routes,
            proxy_exports: BTreeMap::new(),
            direct_inputs: Vec::new(),
            process_pid: None,
            published: true,
        };

        assert!(
            !dynamic_site_controller_overlay_required(&[child(Vec::new())]),
            "VM sites controlled from a direct site can publish ordinary dynamic children without \
             a local site-controller component"
        );
        assert!(
            !dynamic_site_controller_overlay_required(&[child(vec![InboundRoute {
                route_id: "empty".to_string(),
                capability: "component".to_string(),
                capability_kind: Some("framework.component".to_string()),
                capability_profile: None,
                protocol: MeshProtocol::Http,
                http_plugins: Vec::new(),
                target: InboundTarget::Local { port: 8080 },
                allowed_issuers: Vec::new(),
            }])]),
            "routes with no dynamic issuers do not require a controller overlay"
        );
        assert!(
            dynamic_site_controller_overlay_required(&[child(vec![InboundRoute {
                route_id: "granted".to_string(),
                capability: "component".to_string(),
                capability_kind: Some("framework.component".to_string()),
                capability_profile: None,
                protocol: MeshProtocol::Http,
                http_plugins: Vec::new(),
                target: InboundTarget::Local { port: 8080 },
                allowed_issuers: vec!["/job-dynamic".to_string()],
            }])]),
            "controller overlays are still required when a dynamic child receives a granted \
             framework.component route"
        );
    }

    #[test]
    fn project_dynamic_direct_router_surface_creates_child_control_aliases() {
        let temp = tempfile::tempdir().expect("tempdir should be created");
        let site_artifact = temp.path().join("site-artifact");
        let site_state_root = temp.path().join("state").join("direct_local");
        let child_artifact = site_state_root
            .join("framework-component")
            .join("children")
            .join("1")
            .join("artifact");
        fs::create_dir_all(site_artifact.join(".amber").join("control"))
            .expect("site artifact control dir should exist");
        fs::create_dir_all(child_artifact.join(".amber")).expect("child artifact dir should exist");

        let site_current = super::super::direct_current_control_socket_path(&site_artifact);
        if let Some(parent) = site_current.parent() {
            fs::create_dir_all(parent).expect("site current control dir should exist");
        }
        let site_runtime = temp.path().join("router-runtime.sock");
        fs::write(&site_runtime, []).expect("fake router runtime socket placeholder should exist");
        super::super::ensure_direct_control_socket_link(
            &site_current,
            &site_runtime,
            "site current control symlink",
        )
        .expect("site current control symlink should be created");
        super::super::ensure_direct_control_socket_link(
            &site_artifact
                .join(".amber")
                .join("control")
                .join("router-control.sock"),
            &site_current,
            "site artifact control symlink",
        )
        .expect("site artifact control symlink should be created");
        write_json(
            &super::super::direct_runtime_state_path(&child_artifact),
            &super::super::DirectRuntimeState::default(),
        )
        .expect("child direct runtime state should be written");

        let plan = runtime_api::SiteControllerRuntimePlan {
            schema: "test".to_string(),
            version: 1,
            run_id: "run-123".to_string(),
            mesh_scope: "mesh".to_string(),
            run_root: temp.path().display().to_string(),
            site_id: "direct_local".to_string(),
            kind: SiteKind::Direct,
            router_identity_id: "/site/direct_local/router".to_string(),
            local_router_control: None,
            artifact_dir: site_artifact.display().to_string(),
            site_state_root: site_state_root.display().to_string(),
            listen_addr: "127.0.0.1:32000".parse().expect("listen addr"),
            storage_root: None,
            runtime_root: None,
            router_mesh_port: Some(24000),
            compose_project: None,
            kubernetes_namespace: None,
            context: None,
            observability_endpoint: None,
            vm_endpoint_forward_ready_timeout_secs: None,
            launch_env: BTreeMap::new(),
        };
        let child = SiteControllerRuntimeChildRecord {
            child_id: 1,
            artifact_root: child_artifact.display().to_string(),
            assigned_components: vec!["/job-1".to_string()],
            controller_routes: Vec::new(),
            proxy_exports: BTreeMap::new(),
            direct_inputs: Vec::new(),
            process_pid: None,
            published: true,
        };

        project_dynamic_direct_router_surface(&plan, &child)
            .expect("direct child router surface should project");

        let state: super::super::DirectRuntimeState = read_json(
            &super::super::direct_runtime_state_path(&child_artifact),
            "direct runtime state",
        )
        .expect("projected direct runtime state should be readable");
        assert_eq!(state.router_mesh_port, Some(24000));

        let child_current = super::super::direct_current_control_socket_path(&child_artifact);
        assert_eq!(
            fs::read_link(&child_current).expect("child current control alias should exist"),
            site_current,
            "child current alias should point at the site current control alias",
        );
        assert_eq!(
            fs::read_link(
                child_artifact
                    .join(".amber")
                    .join("control")
                    .join("router-control.sock")
            )
            .expect("child artifact control alias should exist"),
            child_current,
            "child artifact control alias should point at the child current alias",
        );
    }

    #[test]
    fn cleanup_dynamic_site_children_removes_child_roots_and_clears_state() {
        let temp = tempfile::tempdir().expect("tempdir should be created");
        let site_state_root = temp.path().join("state").join("direct_local");
        let child_root =
            runtime_api::site_controller_runtime_child_root_for_site(&site_state_root, 7);
        fs::create_dir_all(child_root.join("artifact")).expect("child artifact dir should exist");
        fs::write(child_root.join("artifact").join("marker.txt"), "marker")
            .expect("child marker should be written");
        write_json(
            &site_controller_runtime_state_path(&site_state_root),
            &SiteControllerRuntimeState {
                schema: SITE_CONTROLLER_RUNTIME_STATE_SCHEMA.to_string(),
                version: SITE_CONTROLLER_RUNTIME_STATE_VERSION,
                run_id: "run-123".to_string(),
                site_id: "direct_local".to_string(),
                kind: SiteKind::Direct,
                direct_input_overlay_providers: BTreeSet::new(),
                children: BTreeMap::from([(
                    7,
                    SiteControllerRuntimeChildRecord {
                        child_id: 7,
                        artifact_root: child_root.join("artifact").display().to_string(),
                        assigned_components: Vec::new(),
                        controller_routes: Vec::new(),
                        proxy_exports: BTreeMap::new(),
                        direct_inputs: Vec::new(),
                        process_pid: None,
                        published: true,
                    },
                )]),
            },
        )
        .expect("site controller runtime state should be written");

        cleanup_dynamic_site_children(&site_state_root, SiteKind::Direct)
            .expect("dynamic site children should be cleaned");

        let state: SiteControllerRuntimeState = read_json(
            &site_controller_runtime_state_path(&site_state_root),
            "site controller runtime state",
        )
        .expect("site controller runtime state should be readable");
        assert!(state.children.is_empty());
        assert!(!child_root.exists());
    }

    #[test]
    fn inject_site_controller_peer_router_routes_adds_local_inbound_and_peer_outbound_routes() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("mesh-provision-plan.json");
        write_json(
            &path,
            &MeshProvisionPlan {
                version: amber_mesh::MESH_PROVISION_PLAN_VERSION.to_string(),
                identity_seed: None,
                existing_peer_identities: Vec::new(),
                targets: vec![
                MeshProvisionTarget {
                    kind: MeshProvisionTargetKind::Component,
                    config: MeshConfigTemplate {
                        identity: amber_mesh::MeshIdentityTemplate {
                            id: "/site/local/controller".to_string(),
                            mesh_scope: None,
                        },
                        mesh_listen: "127.0.0.1:23001".parse().expect("mesh listen"),
                        control_listen: None,
                        dynamic_caps_listen: None,
                        control_allow: None,
                        peers: Vec::new(),
                        inbound: vec![InboundRoute {
                            route_id: amber_mesh::component_route_id(
                                "/site/local/controller",
                                amber_mesh::FRAMEWORK_COMPONENT_CONTROLLER_INTERNAL_PROVIDE_NAME,
                                MeshProtocol::Http,
                            ),
                            capability: amber_mesh::FRAMEWORK_COMPONENT_CONTROLLER_INTERNAL_PROVIDE_NAME.to_string(),
                            capability_kind: None,
                            capability_profile: None,
                            protocol: MeshProtocol::Http,
                            http_plugins: Vec::new(),
                            target: InboundTarget::Local { port: 8080 },
                            allowed_issuers: vec!["/site/local/router".to_string()],
                        }],
                        outbound: Vec::new(),
                        transport: amber_mesh::TransportConfig::NoiseIk {},
                    },
                    output: MeshProvisionOutput::Filesystem {
                        dir: "mesh/controller".to_string(),
                    },
                },
                MeshProvisionTarget {
                    kind: MeshProvisionTargetKind::Router,
                    config: MeshConfigTemplate {
                        identity: amber_mesh::MeshIdentityTemplate {
                            id: "/site/local/router".to_string(),
                            mesh_scope: None,
                        },
                        mesh_listen: "127.0.0.1:24000".parse().expect("mesh listen"),
                        control_listen: Some("127.0.0.1:24100".parse().expect("control listen")),
                        dynamic_caps_listen: None,
                        control_allow: None,
                        peers: Vec::new(),
                        inbound: Vec::new(),
                        outbound: Vec::new(),
                        transport: amber_mesh::TransportConfig::NoiseIk {},
                    },
                    output: MeshProvisionOutput::Filesystem {
                        dir: "mesh/router".to_string(),
                    },
                }
            ],
            },
        )
        .expect("write mesh plan");

        inject_site_controller_peer_router_routes(
            temp.path(),
            "local",
            &["/site/peer/router".to_string()],
            &[SiteControllerPeerRouterRoute {
                site_id: "peer".to_string(),
                peer_router: MeshIdentityPublic {
                    id: "/site/peer/router".to_string(),
                    public_key: [7; 32],
                    mesh_scope: Some("amber.test".to_string()),
                },
                peer_addr: "10.0.0.20:24000".to_string(),
                listen_addr: "127.0.0.1".to_string(),
                listen_port: 25001,
            }],
        )
        .expect("inject routes");

        let plan: MeshProvisionPlan = read_json(&path, "mesh provision plan").expect("plan");
        let router = plan
            .targets
            .iter()
            .find(|target| matches!(target.kind, MeshProvisionTargetKind::Router))
            .expect("router target should remain present");
        assert!(
            router.config.inbound.iter().any(|route| {
                route.route_id == site_controller_internal_route_id("local")
                    && route.capability == SITE_CONTROLLER_INTERNAL_CAPABILITY
                    && route.allowed_issuers == vec!["/site/peer/router".to_string()]
                    && matches!(
                        route.target,
                        InboundTarget::MeshForward {
                            ref peer_id,
                            ref peer_addr,
                            ref route_id,
                            ref capability,
                    } if peer_id == "/site/local/controller"
                        && peer_addr == "127.0.0.1:23001"
                            && route_id
                                == &amber_mesh::component_route_id(
                                    "/site/local/controller",
                                    amber_mesh::FRAMEWORK_COMPONENT_CONTROLLER_INTERNAL_PROVIDE_NAME,
                                    MeshProtocol::Http,
                                )
                            && capability
                                == amber_mesh::FRAMEWORK_COMPONENT_CONTROLLER_INTERNAL_PROVIDE_NAME
                    )
            }),
            "router should expose a local inbound route for peer site-controller traffic",
        );
        assert!(
            router.config.outbound.iter().any(|route| {
                route.route_id == site_controller_internal_route_id("peer")
                    && route.capability == SITE_CONTROLLER_INTERNAL_CAPABILITY
                    && route.peer_id == "/site/peer/router"
                    && route.peer_addr == "10.0.0.20:24000"
                    && route.listen_addr.as_deref() == Some("127.0.0.1")
                    && route.listen_port == 25001
            }),
            "router should publish a local outbound listener for the peer site controller",
        );
        assert!(
            plan.existing_peer_identities.iter().any(|identity| {
                identity.id == "/site/peer/router"
                    && identity.public_key == [7; 32]
                    && identity.mesh_scope.as_deref() == Some("amber.test")
            }),
            "router mesh plan should carry the peer router identity needed to provision the route",
        );
    }

    #[test]
    fn compose_router_port_helpers_rewrite_mesh_publish() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("compose.yaml"),
            r#"
services:
  amber-router:
    image: ghcr.io/rdi-foundation/amber-router:v0.2.x
    ports:
      - "127.0.0.1::24000"
"#,
        )
        .expect("compose yaml should write");

        set_compose_router_published_mesh_port(temp.path(), 34000).expect("rewrite mesh port");

        let rendered =
            fs::read_to_string(temp.path().join("compose.yaml")).expect("compose yaml should read");
        assert!(
            rendered.contains("0.0.0.0:34000:24000"),
            "mesh port should be rewritten to a deterministic host publish:\n{rendered}"
        );
    }
}
