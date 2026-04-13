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

pub(super) fn dynamic_input_route_mesh_protocol(
    input: &DynamicInputRouteRecord,
) -> Result<MeshProtocol> {
    let protocol = input
        .protocol
        .parse::<NetworkProtocol>()
        .map_err(|err| miette::miette!("invalid dynamic routed-input protocol: {err}"))?;
    mesh_protocol(protocol)
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

pub(super) fn dynamic_input_route_route_id(
    input: &DynamicInputRouteRecord,
    protocol: MeshProtocol,
) -> String {
    match &input.target {
        DynamicInputRouteTarget::ComponentProvide { provide } => {
            component_route_id(&input.provider_component, provide, protocol)
        }
    }
}

pub(super) fn dynamic_input_route_capability(input: &DynamicInputRouteRecord) -> String {
    match &input.target {
        DynamicInputRouteTarget::ComponentProvide { provide } => provide.clone(),
    }
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

pub(super) fn dynamic_input_route_http_plugins(
    input: &DynamicInputRouteRecord,
    protocol: MeshProtocol,
) -> Vec<HttpRoutePlugin> {
    dynamic_proxy_export_http_plugins(
        &DynamicProxyExportRecord {
            component_id: 0,
            component: input.provider_component.clone(),
            provide: dynamic_input_route_capability(input),
            protocol: input.protocol.clone(),
            capability_kind: input.capability_kind.clone(),
            capability_profile: input.capability_profile.clone(),
            target_port: 0,
        },
        protocol,
    )
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

pub(super) fn overlay_issuer_sets(
    routed_inputs: &[DynamicInputRouteRecord],
) -> Result<BTreeMap<String, BTreeSet<String>>> {
    dynamic_route_issuer_grants(&[SiteControllerRuntimeChildRecord {
        child_id: 0,
        artifact_root: String::new(),
        assigned_components: Vec::new(),
        proxy_exports: BTreeMap::new(),
        direct_inputs: Vec::new(),
        routed_inputs: routed_inputs.to_vec(),
        process_pid: None,
        published: false,
    }])
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

pub(super) fn overlay_upsert_route(routes: &mut Vec<InboundRoute>, route: InboundRoute) {
    if let Some(existing) = routes
        .iter_mut()
        .find(|existing| existing.route_id == route.route_id)
    {
        *existing = route;
    } else {
        routes.push(route);
    }
}

pub(super) fn routed_input_overlay_route(
    input: &DynamicInputRouteRecord,
    provider_peer_addr: &str,
    allowed_issuers: Vec<String>,
) -> Result<InboundRoute> {
    let protocol = dynamic_input_route_mesh_protocol(input)?;
    let (target_route_id, capability) = match &input.target {
        DynamicInputRouteTarget::ComponentProvide { provide } => (
            component_route_id(&input.provider_component, provide, protocol),
            provide.clone(),
        ),
    };
    Ok(InboundRoute {
        route_id: dynamic_input_route_route_id(input, protocol),
        capability: dynamic_input_route_capability(input),
        capability_kind: Some(input.capability_kind.clone()),
        capability_profile: input.capability_profile.clone(),
        protocol,
        http_plugins: dynamic_input_route_http_plugins(input, protocol),
        target: InboundTarget::MeshForward {
            peer_addr: provider_peer_addr.to_string(),
            peer_id: input.provider_component.clone(),
            route_id: target_route_id,
            capability,
        },
        allowed_issuers,
    })
}

pub(super) fn augment_route_overlay_payload(
    payload: &mut StoredRouteOverlayPayload,
    proxy_exports: &BTreeMap<String, DynamicProxyExportRecord>,
    routed_inputs: &[DynamicInputRouteRecord],
    provider_peer_addrs: &BTreeMap<String, String>,
    peer_identities: &BTreeMap<String, MeshIdentityPublic>,
    allowed_issuers_by_route: Option<&BTreeMap<String, BTreeSet<String>>>,
    skip_missing_providers: bool,
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

    for input in routed_inputs {
        let Some(provider_peer_addr) = provider_peer_addrs.get(&input.provider_component) else {
            if skip_missing_providers {
                continue;
            }
            return Err(miette::miette!(
                "dynamic route overlay is missing a live peer address for {}",
                input.provider_component
            ));
        };
        overlay_upsert_peer(
            &mut payload.peers,
            peer_identities,
            &input.provider_component,
        )?;
        let route_id =
            dynamic_input_route_route_id(input, dynamic_input_route_mesh_protocol(input)?);
        let allowed_issuers = allowed_issuers_by_route
            .and_then(|issuers| issuers.get(&route_id))
            .map(|issuers| issuers.iter().cloned().collect())
            .unwrap_or_default();
        overlay_upsert_route(
            &mut payload.inbound_routes,
            routed_input_overlay_route(input, provider_peer_addr, allowed_issuers)?,
        );
    }

    Ok(())
}

pub(super) fn routed_input_router_peer_addr(
    kind: SiteKind,
    router_mesh_port: Option<u16>,
) -> Result<String> {
    let router_mesh_port = router_mesh_port.ok_or_else(|| {
        miette::miette!("site {kind:?} is missing its router mesh port for routed child inputs")
    })?;
    Ok(match kind {
        SiteKind::Direct | SiteKind::Vm => format!("127.0.0.1:{router_mesh_port}"),
        SiteKind::Compose => format!("{COMPOSE_ROUTER_SERVICE_NAME}:{router_mesh_port}"),
        SiteKind::Kubernetes => {
            format!("{KUBERNETES_ROUTER_COMPONENT_NAME}:{router_mesh_port}")
        }
    })
}

pub(super) fn router_mesh_port_from_plan(
    mesh_plan: &MeshProvisionPlan,
    artifact_kind: &str,
) -> Result<u16> {
    mesh_plan
        .targets
        .iter()
        .find(|target| matches!(target.kind, MeshProvisionTargetKind::Router))
        .map(|target| target.config.mesh_listen.port())
        .ok_or_else(|| {
            miette::miette!("{artifact_kind} mesh provision plan is missing its router mesh target")
        })
}

pub(super) fn rewrite_dynamic_routed_inputs(
    mesh_plan: &mut MeshProvisionPlan,
    routed_inputs: &[DynamicInputRouteRecord],
    kind: SiteKind,
    router_identity_id: &str,
    router_mesh_port: Option<u16>,
) -> Result<()> {
    if routed_inputs.is_empty() {
        return Ok(());
    }

    let router_peer_addr = routed_input_router_peer_addr(kind, router_mesh_port)?;
    for input in routed_inputs {
        let protocol = dynamic_input_route_mesh_protocol(input)?;
        let component_target = mesh_plan
            .targets
            .iter_mut()
            .find(|target| {
                matches!(target.kind, MeshProvisionTargetKind::Component)
                    && target.config.identity.id == input.component
            })
            .ok_or_else(|| {
                miette::miette!(
                    "dynamic routed input {}.{} is missing component {} in the mesh provision plan",
                    input.component,
                    input.slot,
                    input.component
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

        let route_id = dynamic_input_route_route_id(input, protocol);
        let capability = dynamic_input_route_capability(input);
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
            route.peer_addr = router_peer_addr.clone();
            route.peer_id = router_identity_id.to_string();
            route.capability = capability.clone();
            route.capability_kind = Some(input.capability_kind.clone());
            route.capability_profile = input.capability_profile.clone();
            route.http_plugins = dynamic_input_route_http_plugins(input, protocol);
        }
        if !matched {
            return Err(miette::miette!(
                "dynamic routed input {}.{} is missing an outbound route in the mesh provision \
                 plan",
                input.component,
                input.slot
            ));
        }
    }

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
            route.peer_addr = provider_runtime.host_mesh_addr.clone();
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

pub(super) fn rewrite_dynamic_routed_inputs_in_artifact(
    artifact_root: &Path,
    routed_inputs: &[DynamicInputRouteRecord],
    kind: SiteKind,
    router_identity_id: &str,
    router_mesh_port: Option<u16>,
) -> Result<()> {
    if routed_inputs.is_empty() {
        return Ok(());
    }
    let path = artifact_root.join("mesh-provision-plan.json");
    let mut mesh_plan: MeshProvisionPlan = read_json(&path, "mesh provision plan")?;
    rewrite_dynamic_routed_inputs(
        &mut mesh_plan,
        routed_inputs,
        kind,
        router_identity_id,
        router_mesh_port,
    )?;
    write_json(&path, &mesh_plan)
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

pub(super) fn write_direct_vm_startup_route_overlay_payload(
    artifact_root: &Path,
    _artifact_kind: &str,
    routed_inputs: &[DynamicInputRouteRecord],
    provider_peer_addrs: &BTreeMap<String, String>,
    existing_site_peer_identities: &BTreeMap<String, MeshIdentityPublic>,
) -> Result<()> {
    if routed_inputs.is_empty() {
        return Ok(());
    }
    let allowed_issuers = overlay_issuer_sets(routed_inputs)?;
    let mut payload = StoredRouteOverlayPayload {
        peers: Vec::new(),
        inbound_routes: Vec::new(),
    };
    augment_route_overlay_payload(
        &mut payload,
        &BTreeMap::new(),
        routed_inputs,
        provider_peer_addrs,
        existing_site_peer_identities,
        Some(&allowed_issuers),
        true,
    )?;
    if payload.inbound_routes.is_empty() {
        return Ok(());
    }
    write_dynamic_route_overlay_payload(artifact_root, &payload)
}

pub(super) fn write_direct_vm_live_route_overlay_payload(
    artifact_root: &Path,
    assigned_components: &[String],
    proxy_exports: &BTreeMap<String, DynamicProxyExportRecord>,
    routed_inputs: &[DynamicInputRouteRecord],
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
        routed_inputs,
        provider_peer_addrs,
        peer_identities,
        None,
        false,
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
    let state_path = Path::new(&plan.site_state_root).join("manager-state.json");
    if state_path.is_file() {
        let state: SiteManagerState = read_json(&state_path, "site manager state")?;
        if let Some(raw) = state.router_control {
            return parse_control_endpoint(&raw);
        }
    }
    if let Some(raw) = plan.local_router_control.as_deref() {
        return parse_control_endpoint(raw);
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

pub(super) fn dynamic_route_issuer_grants(
    children: &[SiteControllerRuntimeChildRecord],
) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let mut issuers_by_route_id = BTreeMap::<String, BTreeSet<String>>::new();
    for child in children {
        for input in &child.routed_inputs {
            let route_id =
                dynamic_input_route_route_id(input, dynamic_input_route_mesh_protocol(input)?);
            issuers_by_route_id
                .entry(route_id)
                .or_default()
                .insert(input.component.clone());
        }
    }
    Ok(issuers_by_route_id)
}

pub(super) fn load_published_component_peers(
    plan: &SiteControllerRuntimePlan,
    published_children: &[SiteControllerRuntimeChildRecord],
) -> Result<BTreeMap<String, MeshPeer>> {
    let mut component_peers = BTreeMap::new();
    for child in published_children {
        if child.assigned_components.is_empty() {
            continue;
        }
        let artifact_root = Path::new(&child.artifact_root);
        let runtime_root = child_overlay_runtime_root(plan, child);
        let provision: MeshProvisionPlan = read_json(
            &artifact_root.join("mesh-provision-plan.json"),
            "mesh provision plan",
        )?;
        for component in &child.assigned_components {
            let target = provision
                .targets
                .iter()
                .find(|target| {
                    matches!(target.kind, MeshProvisionTargetKind::Component)
                        && target.config.identity.id == *component
                })
                .ok_or_else(|| {
                    miette::miette!(
                        "published child {} is missing component {} in its mesh provision plan",
                        child.child_id,
                        component
                    )
                })?;
            let identity = match &target.output {
                MeshProvisionOutput::Filesystem { dir } => read_json(
                    &runtime_root.join(dir).join(MESH_IDENTITY_FILENAME),
                    "mesh identity",
                )?,
                MeshProvisionOutput::KubernetesSecret { name, namespace } => {
                    load_kubernetes_mesh_identity_secret(plan, name, namespace.as_deref())?
                }
            };
            component_peers.insert(
                component.clone(),
                MeshPeer {
                    id: identity.id.clone(),
                    public_key: identity.public_key().into_diagnostic()?,
                },
            );
        }
    }
    Ok(component_peers)
}

pub(super) fn apply_dynamic_route_issuer_grants(
    peers: &mut Vec<MeshPeer>,
    inbound_routes: &mut [InboundRoute],
    issuers_by_route_id: &BTreeMap<String, BTreeSet<String>>,
    component_peers: &BTreeMap<String, MeshPeer>,
) -> Result<()> {
    let mut known_peer_ids = peers
        .iter()
        .map(|peer| peer.id.clone())
        .collect::<BTreeSet<_>>();
    for route in inbound_routes {
        let Some(issuers) = issuers_by_route_id.get(&route.route_id) else {
            continue;
        };
        route.allowed_issuers = issuers.iter().cloned().collect();
        for issuer in issuers {
            if known_peer_ids.contains(issuer) {
                continue;
            }
            let peer = component_peers.get(issuer).ok_or_else(|| {
                miette::miette!(
                    "dynamic route {} references published issuer {} with no live mesh peer",
                    route.route_id,
                    issuer
                )
            })?;
            peers.push(peer.clone());
            known_peer_ids.insert(issuer.clone());
        }
    }
    Ok(())
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

pub(super) async fn reconcile_dynamic_direct_input_overlays(
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
    let grants = dynamic_direct_input_grants(&published_children)?;
    for (component, runtime) in &live_components {
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

    let issuers_by_route_id = dynamic_route_issuer_grants(issuer_children)?;
    let component_peers = load_published_component_peers(&app.plan, issuer_children)?;
    for child in overlay_children {
        let artifact_root = Path::new(&child.artifact_root);
        let runtime_root = child_overlay_runtime_root(&app.plan, child);
        let (mut peers, mut inbound_routes) =
            child_router_overlay_payload(&app.plan, artifact_root, &runtime_root)?;
        apply_dynamic_route_issuer_grants(
            &mut peers,
            &mut inbound_routes,
            &issuers_by_route_id,
            &component_peers,
        )?;
        if inbound_routes.is_empty() {
            continue;
        }
        let endpoint = site_router_control_endpoint(&app.plan)?;
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
    let artifact_root = Path::new(&child.artifact_root);
    let runtime_root = child_overlay_runtime_root(plan, child);
    let (peers, inbound_routes) = child_router_overlay_payload(plan, artifact_root, &runtime_root)?;
    if inbound_routes.is_empty() {
        return Ok(());
    }
    let endpoint = site_router_control_endpoint(plan)?;
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
    let endpoint = site_router_control_endpoint(plan)?;
    revoke_route_overlay_with_retry(
        &endpoint,
        &dynamic_child_route_overlay_id(plan, child.child_id),
        Duration::from_secs(30),
    )
    .await
}

#[cfg(test)]
mod direct_input_tests {
    use std::fs;

    use amber_mesh::MeshConfigTemplate;

    use super::*;

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
                host_mesh_addr: "10.0.0.20:24001".to_string(),
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
    fn dynamic_route_issuer_grants_include_component_provide_inputs() {
        let issuers = dynamic_route_issuer_grants(&[SiteControllerRuntimeChildRecord {
            child_id: 7,
            artifact_root: "/tmp/child".to_string(),
            assigned_components: vec!["/sibling".to_string()],
            proxy_exports: BTreeMap::new(),
            direct_inputs: Vec::new(),
            routed_inputs: vec![DynamicInputRouteRecord {
                component: "/sibling".to_string(),
                slot: "upstream".to_string(),
                provider_component: "/provider".to_string(),
                protocol: "http".to_string(),
                capability_kind: "http".to_string(),
                capability_profile: None,
                target: DynamicInputRouteTarget::ComponentProvide {
                    provide: "http".to_string(),
                },
            }],
            process_pid: None,
            published: true,
        }])
        .expect("component-provide routed inputs should produce issuer grants");

        assert_eq!(
            issuers.get("component:/provider:http:http"),
            Some(&BTreeSet::from(["/sibling".to_string()]))
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
                children: BTreeMap::from([(
                    7,
                    SiteControllerRuntimeChildRecord {
                        child_id: 7,
                        artifact_root: child_root.join("artifact").display().to_string(),
                        assigned_components: Vec::new(),
                        proxy_exports: BTreeMap::new(),
                        direct_inputs: Vec::new(),
                        routed_inputs: Vec::new(),
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
                targets: vec![MeshProvisionTarget {
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
                }],
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
        let router = &plan.targets[0];
        assert!(
            router.config.inbound.iter().any(|route| {
                route.route_id == site_controller_internal_route_id("local")
                    && route.capability == SITE_CONTROLLER_INTERNAL_CAPABILITY
                    && route.allowed_issuers == vec!["/site/peer/router".to_string()]
                    && matches!(
                        route.target,
                        InboundTarget::External { ref url_env, optional }
                            if url_env == amber_mesh::FRAMEWORK_COMPONENT_CONTROLLER_URL_ENV
                                && !optional
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
    fn compose_router_port_helpers_rewrite_mesh_publish_and_add_controller_ports() {
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
        add_compose_router_published_route_ports(temp.path(), &[34001, 34002])
            .expect("append controller ports");

        let rendered =
            fs::read_to_string(temp.path().join("compose.yaml")).expect("compose yaml should read");
        assert!(
            rendered.contains("0.0.0.0:34000:24000"),
            "mesh port should be rewritten to a deterministic host publish:\n{rendered}"
        );
        assert!(
            rendered.contains("127.0.0.1:34001:34001"),
            "controller route port 34001 should be published on loopback:\n{rendered}"
        );
        assert!(
            rendered.contains("127.0.0.1:34002:34002"),
            "controller route port 34002 should be published on loopback:\n{rendered}"
        );
    }
}
