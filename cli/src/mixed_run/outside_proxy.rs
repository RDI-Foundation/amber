use super::*;

pub(crate) fn maybe_resolve_proxy_run_target(
    target: &str,
    site_id: Option<&str>,
    storage_root_override: Option<&Path>,
) -> Result<Option<ResolvedRunProxyTarget>> {
    let target_path = Path::new(target);
    if target_path.exists() {
        let run_root = canonicalize_existing_path(target_path, "proxy target")?;
        if run_root.is_file()
            && run_root.file_name().and_then(|name| name.to_str()) == Some("receipt.json")
        {
            return resolve_proxy_run_root(
                run_root
                    .parent()
                    .ok_or_else(|| miette::miette!("receipt path is missing a parent run root"))?,
                site_id,
            )
            .map(Some);
        }
        if run_root.is_dir() && receipt_path(&run_root).is_file() {
            return resolve_proxy_run_root(&run_root, site_id).map(Some);
        }
        return Ok(None);
    }

    let storage_root = mixed_run_storage_root(storage_root_override)?;
    let run_root = storage_root.join("runs").join(target);
    if !receipt_path(&run_root).is_file() {
        return Ok(None);
    }
    resolve_proxy_run_root(&run_root, site_id).map(Some)
}

pub(crate) fn maybe_resolve_run_root(
    target: &str,
    storage_root_override: Option<&Path>,
) -> Result<Option<PathBuf>> {
    let target_path = Path::new(target);
    if target_path.exists() {
        let path = canonicalize_existing_path(target_path, "run target")?;
        if path.is_file() && path.file_name().and_then(|name| name.to_str()) == Some("receipt.json")
        {
            return Ok(path.parent().map(Path::to_path_buf));
        }
        if path.is_dir() && receipt_path(&path).is_file() {
            return Ok(Some(path));
        }
        return Ok(None);
    }

    let storage_root = mixed_run_storage_root(storage_root_override)?;
    let run_root = storage_root.join("runs").join(target);
    if receipt_path(&run_root).is_file() {
        return Ok(Some(run_root));
    }
    Ok(None)
}

pub(crate) fn spawn_run_outside_proxy(
    run_root: &Path,
    slot_bindings: &BTreeMap<String, String>,
    export_bindings: &BTreeMap<String, SocketAddr>,
) -> Result<Child> {
    let plan_path = write_run_outside_proxy_plan(run_root, slot_bindings, export_bindings)?;
    spawn_detached_child(run_root, &run_root.join("outside-proxy.log"), |cmd| {
        cmd.arg("run-outside-proxy").arg("--plan").arg(&plan_path);
    })
}

pub(crate) fn write_run_outside_proxy_plan(
    run_root: &Path,
    slot_bindings: &BTreeMap<String, String>,
    export_bindings: &BTreeMap<String, SocketAddr>,
) -> Result<PathBuf> {
    if slot_bindings.is_empty() && export_bindings.is_empty() {
        return Err(miette::miette!(
            "outside proxy requires at least one export or external slot binding"
        ));
    }
    let plan = OutsideProxyPlan {
        schema: OUTSIDE_PROXY_PLAN_SCHEMA.to_string(),
        version: OUTSIDE_PROXY_PLAN_VERSION,
        run_root: run_root.display().to_string(),
        slot_bindings: slot_bindings.clone(),
        export_bindings: export_bindings
            .iter()
            .map(|(name, addr)| (name.clone(), addr.to_string()))
            .collect(),
    };
    let plan_path = outside_proxy_plan_path(run_root);
    write_json(&plan_path, &plan)?;
    Ok(plan_path)
}

pub(crate) async fn wait_for_run_outside_proxy_ready(run_root: &Path) -> Result<()> {
    let state_path = outside_proxy_state_path(run_root);
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if state_path.is_file() {
            let _: OutsideProxyState = read_json(&state_path, "outside proxy state")?;
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }
    Err(miette::miette!(
        "timed out waiting for outside proxy under {}",
        run_root.display()
    ))
}

pub(crate) async fn run_outside_proxy(plan_path: PathBuf) -> Result<()> {
    let plan: OutsideProxyPlan = read_json(&plan_path, "outside proxy plan")?;
    if plan.schema != OUTSIDE_PROXY_PLAN_SCHEMA || plan.version != OUTSIDE_PROXY_PLAN_VERSION {
        return Err(miette::miette!(
            "invalid outside proxy plan {}",
            plan_path.display()
        ));
    }

    let run_root = PathBuf::from(&plan.run_root);
    let receipt: RunReceipt = read_json(&receipt_path(&run_root), "run receipt")?;
    let run_plan: RunPlan = read_json(&run_plan_path(&run_root), "run plan")?;
    let interface = collect_run_interface(&run_plan)?;
    let slot_bindings = plan
        .slot_bindings
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect::<Vec<_>>();
    let export_bindings = plan
        .export_bindings
        .iter()
        .map(|(name, addr)| {
            Ok((
                name.clone(),
                addr.parse::<SocketAddr>()
                    .into_diagnostic()
                    .wrap_err_with(|| format!("invalid outside proxy export binding `{addr}`"))?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    validate_slot_bindings(&interface, &slot_bindings)?;
    validate_export_bindings(&interface, &export_bindings)?;

    let context = build_run_outside_proxy_context(&run_root, &run_plan, &receipt)?;
    let mesh_listen =
        outside_proxy_mesh_listen_addr(&context, &slot_bindings, reserve_loopback_port()?)?;
    let outside_identity = build_outside_proxy_identity(&receipt.run_id, &context.mesh_scope);
    let outside_public = MeshIdentityPublic::from_identity(&outside_identity);
    let mut peers = BTreeMap::<String, MeshPeer>::new();
    let mut inbound = Vec::new();
    let mut outbound = Vec::new();
    let mut export_urls = BTreeMap::new();

    for (slot_name, raw_url) in &plan.slot_bindings {
        let slot = context.slots.get(slot_name).ok_or_else(|| {
            miette::miette!("outside proxy slot `{slot_name}` is not part of the run")
        })?;
        let protocol = mesh_protocol_for_capability(slot.kind)?;
        let route_id = component_route_id(&outside_identity.id, slot_name, protocol);
        inbound.push(InboundRoute {
            route_id: route_id.clone(),
            capability: slot_name.clone(),
            capability_kind: Some(slot.kind.to_string()),
            capability_profile: None,
            protocol,
            http_plugins: Vec::new(),
            target: InboundTarget::External {
                url_env: slot.url_env.clone(),
                optional: !slot.required,
            },
            allowed_issuers: slot
                .consumer_sites
                .iter()
                .map(|site_id| {
                    context
                        .sites
                        .get(site_id)
                        .expect("consumer site should exist")
                        .router_identity
                        .id
                        .clone()
                })
                .collect(),
        });
        // This short-lived proxy process owns its environment and uses env vars to feed router
        // external targets. No other work in this process depends on these keys.
        unsafe {
            env::set_var(&slot.url_env, raw_url);
        }
        for site_id in &slot.consumer_sites {
            let consumer = context
                .sites
                .get(site_id)
                .expect("consumer site should exist");
            peers
                .entry(consumer.router_identity.id.clone())
                .or_insert(MeshPeer {
                    id: consumer.router_identity.id.clone(),
                    public_key: consumer.router_identity.public_key,
                });
            let mesh_url = outside_slot_mesh_url(
                mesh_listen,
                &outside_public,
                &route_id,
                slot_name,
                consumer.receipt.kind,
            )?;
            register_external_slot_with_retry(
                &consumer.router_control,
                slot_name,
                &mesh_url,
                ROUTER_CONTROL_TIMEOUT,
            )
            .await?;
        }
    }

    for (export_name, listen) in &export_bindings {
        let export = context.exports.get(export_name).ok_or_else(|| {
            miette::miette!("outside proxy export `{export_name}` is not part of the run")
        })?;
        let provider = context
            .sites
            .get(&export.site_id)
            .expect("provider site should exist");
        let protocol = mesh_protocol_for_export(&export.protocol)?;
        let peer_key =
            base64::engine::general_purpose::STANDARD.encode(outside_identity.public_key);
        register_export_peer_with_retry(
            &provider.router_control,
            export_name,
            &outside_identity.id,
            &peer_key,
            &export.protocol,
            None,
            ROUTER_CONTROL_TIMEOUT,
        )
        .await?;
        peers
            .entry(provider.router_identity.id.clone())
            .or_insert(MeshPeer {
                id: provider.router_identity.id.clone(),
                public_key: provider.router_identity.public_key,
            });
        outbound.push(OutboundRoute {
            route_id: router_export_route_id(export_name, protocol),
            slot: export_name.clone(),
            capability_kind: None,
            capability_profile: None,
            listen_port: listen.port(),
            listen_addr: Some(listen.ip().to_string()),
            protocol,
            http_plugins: Vec::new(),
            peer_addr: provider.router_addr.to_string(),
            peer_id: provider.router_identity.id.clone(),
            capability: export_name.clone(),
        });
        export_urls.insert(
            export_name.clone(),
            match export.protocol.as_str() {
                "tcp" => format!("tcp://{listen}"),
                _ => format!("http://{listen}"),
            },
        );
    }

    let config = MeshConfig {
        identity: outside_identity,
        mesh_listen,
        control_listen: None,
        dynamic_caps_listen: None,
        control_allow: None,
        peers: peers.into_values().collect(),
        inbound,
        outbound,
        transport: TransportConfig::NoiseIk {},
    };

    let router = tokio::spawn(async move { amber_router::control::run(config).await });
    wait_for_socket_listener(listener_probe_addr(mesh_listen)).await?;
    for listen in export_bindings.iter().map(|(_, listen)| *listen) {
        wait_for_socket_listener(listener_probe_addr(listen)).await?;
    }
    write_json(
        &outside_proxy_state_path(&run_root),
        &OutsideProxyState {
            schema: OUTSIDE_PROXY_STATE_SCHEMA.to_string(),
            version: OUTSIDE_PROXY_STATE_VERSION,
            mesh_listen: mesh_listen.to_string(),
            exports: export_urls,
        },
    )?;

    tokio::select! {
        result = router => {
            match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(err)) => Err(miette::miette!("outside proxy failed: {err}")),
                Err(err) => Err(miette::miette!("outside proxy task failed: {err}")),
            }
        }
        signal = tokio::signal::ctrl_c() => {
            signal.into_diagnostic().wrap_err("failed to wait for Ctrl-C")?;
            Ok(())
        }
    }
}

pub(super) async fn stop_site_from_receipt(
    run_root: &Path,
    site_id: &str,
    site: &SiteReceipt,
) -> Result<()> {
    match site.kind {
        SiteKind::Direct | SiteKind::Vm => {
            shutdown_recorded_processes(site).await?;
        }
        SiteKind::Compose => {
            if let Some(project_name) = site.compose_project.as_deref() {
                let launch_env = read_compose_launch_env(run_root, site_id)?;
                let status = compose_command(Some(project_name), Path::new(&site.artifact_dir))
                    .envs(launch_env)
                    .arg("down")
                    .arg("-v")
                    .arg("--remove-orphans")
                    .status()
                    .into_diagnostic()
                    .wrap_err_with(|| {
                        format!("failed to stop orphaned compose site `{project_name}`")
                    })?;
                if !status.success() {
                    return Err(miette::miette!(
                        "orphaned compose site `{project_name}` failed to stop with status \
                         {status}"
                    ));
                }
            }
        }
        SiteKind::Kubernetes => {
            if let Some(pid) = site.port_forward_pid {
                send_sigterm(pid);
            }
            if let Some(namespace) = site.kubernetes_namespace.as_deref() {
                let status = kubectl_command(site.context.as_deref())
                    .arg("delete")
                    .arg("namespace")
                    .arg(namespace)
                    .arg("--ignore-not-found")
                    .status()
                    .into_diagnostic()
                    .wrap_err_with(|| {
                        format!("failed to stop orphaned kubernetes site `{namespace}`")
                    })?;
                if !status.success() {
                    return Err(miette::miette!(
                        "orphaned kubernetes site `{namespace}` failed to stop with status \
                         {status}"
                    ));
                }
            }
        }
    }
    cleanup_dynamic_site_children(&run_root.join("state").join(site_id), site.kind)?;
    Ok(())
}

pub(super) fn resolve_proxy_run_root(
    run_root: &Path,
    site_id: Option<&str>,
) -> Result<ResolvedRunProxyTarget> {
    let receipt: RunReceipt = read_json(&receipt_path(run_root), "run receipt")?;
    let (site_id, site_receipt) = select_proxy_site(&receipt, site_id)?;
    let artifact_dir = canonicalize_existing_path(
        Path::new(&site_receipt.artifact_dir),
        "site artifact directory",
    )?;
    let state_path = site_state_path(&run_root.join("state"), site_id);
    let live_state = if state_path.is_file() {
        Some(read_json::<SiteManagerState>(
            &state_path,
            "site manager state",
        )?)
    } else {
        None
    };
    let router_control_addr = live_state
        .as_ref()
        .and_then(|state| state.router_control.clone())
        .or_else(|| site_receipt.router_control.clone());
    let router_addr = live_state
        .as_ref()
        .and_then(|state| state.router_mesh_addr.as_deref().map(str::to_string))
        .or_else(|| site_receipt.router_mesh_addr.clone())
        .map(|addr| {
            addr.parse::<SocketAddr>()
                .into_diagnostic()
                .wrap_err_with(|| format!("invalid router mesh addr `{addr}` in run metadata"))
        })
        .transpose()?;
    Ok(ResolvedRunProxyTarget {
        artifact_dir,
        router_control_addr,
        router_addr,
    })
}

pub(super) fn select_proxy_site<'a>(
    receipt: &'a RunReceipt,
    site_id: Option<&str>,
) -> Result<(&'a str, &'a SiteReceipt)> {
    if let Some(site_id) = site_id {
        let (site_key, site) = receipt.sites.get_key_value(site_id).ok_or_else(|| {
            miette::miette!(
                "run `{}` does not contain site `{site_id}`; available sites: {}",
                receipt.run_id,
                receipt.sites.keys().cloned().collect::<Vec<_>>().join(", ")
            )
        })?;
        return Ok((site_key.as_str(), site));
    }

    let mut sites = receipt.sites.iter();
    let Some((only_site_id, only_site)) = sites.next() else {
        return Err(miette::miette!(
            "run `{}` has no sites recorded in its receipt",
            receipt.run_id
        ));
    };
    if sites.next().is_some() {
        return Err(miette::miette!(
            "run `{}` contains multiple sites; pass `--site <site-id>` to `amber proxy`",
            receipt.run_id
        ));
    }
    Ok((only_site_id.as_str(), only_site))
}

pub(super) fn build_run_outside_proxy_context(
    run_root: &Path,
    run_plan: &RunPlan,
    receipt: &RunReceipt,
) -> Result<RunOutsideProxyContext> {
    let mut sites = BTreeMap::new();
    for (site_id, site_receipt) in &receipt.sites {
        let site_plan = run_plan
            .sites
            .get(site_id)
            .ok_or_else(|| miette::miette!("run plan is missing site `{site_id}`"))?;
        let state_path = site_state_path(&run_root.join("state"), site_id);
        let launched = if state_path.is_file() {
            let state: SiteManagerState = read_json(&state_path, "site manager state")?;
            launched_site_from_state(site_plan, &state, &receipt.mesh_scope)
                .or_else(|_| launched_site_from_receipt(site_receipt, &receipt.mesh_scope))
        } else {
            launched_site_from_receipt(site_receipt, &receipt.mesh_scope)
        }?;
        sites.insert(site_id.clone(), launched);
    }

    let mut exports = BTreeMap::<String, RunOutsideExport>::new();
    let mut slots = BTreeMap::<String, RunOutsideSlot>::new();

    for (site_id, site_plan) in &run_plan.sites {
        let metadata = proxy_metadata_view(site_plan)?;
        for (name, export) in metadata.exports {
            if name.starts_with("amber_export_") {
                continue;
            }
            match exports.get(&name) {
                Some(existing)
                    if existing.site_id != *site_id || existing.protocol != export.protocol =>
                {
                    return Err(miette::miette!(
                        "run contains conflicting outside export `{name}`"
                    ));
                }
                Some(_) => {}
                None => {
                    exports.insert(
                        name.clone(),
                        RunOutsideExport {
                            site_id: site_id.clone(),
                            protocol: export.protocol,
                        },
                    );
                }
            }
        }
        for (name, slot) in metadata.external_slots {
            if name.starts_with("amber_link_") {
                continue;
            }
            slots
                .entry(name.clone())
                .and_modify(|existing| {
                    existing.required |= slot.required;
                    if !existing.consumer_sites.contains(site_id) {
                        existing.consumer_sites.push(site_id.clone());
                    }
                })
                .or_insert(RunOutsideSlot {
                    required: slot.required,
                    kind: slot.kind,
                    url_env: slot.url_env,
                    consumer_sites: vec![site_id.clone()],
                });
        }
    }

    for slot in slots.values_mut() {
        slot.consumer_sites.sort();
        slot.consumer_sites.dedup();
    }

    Ok(RunOutsideProxyContext {
        mesh_scope: receipt.mesh_scope.clone(),
        sites,
        exports,
        slots,
    })
}

pub(super) fn proxy_metadata_view(site_plan: &RunSitePlan) -> Result<ProxyMetadata> {
    load_site_proxy_metadata(site_plan)
}

pub(super) fn build_outside_proxy_identity(run_id: &str, mesh_scope: &str) -> MeshIdentity {
    let mut identity = MeshIdentity::generate("outside", Some(mesh_scope.to_string()));
    let suffix = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&identity.public_key[..6]);
    identity.id = format!("/run/{run_id}/outside/{suffix}");
    identity
}

pub(super) fn mesh_protocol_for_capability(kind: CapabilityKind) -> Result<MeshProtocol> {
    match kind.transport() {
        CapabilityTransport::Http => Ok(MeshProtocol::Http),
        CapabilityTransport::NonNetwork => Err(miette::miette!(
            "capability kind `{kind}` cannot be exposed through the outside proxy"
        )),
        _ => Err(miette::miette!(
            "capability kind `{kind}` cannot be exposed through the outside proxy"
        )),
    }
}

pub(super) fn mesh_protocol_for_export(protocol: &str) -> Result<MeshProtocol> {
    Ok(match protocol {
        "http" | "https" => MeshProtocol::Http,
        "tcp" => MeshProtocol::Tcp,
        _ => {
            return Err(miette::miette!(
                "unsupported export protocol `{protocol}` for outside proxy"
            ));
        }
    })
}

pub(super) fn outside_slot_mesh_url(
    mesh_listen: SocketAddr,
    outside_public: &MeshIdentityPublic,
    route_id: &str,
    slot_name: &str,
    consumer_kind: SiteKind,
) -> Result<String> {
    let host = container_host_for_consumer(SiteKind::Direct, consumer_kind);
    let mut mesh_url = Url::parse(&format!("mesh://{}:{}", host, mesh_listen.port()))
        .into_diagnostic()
        .wrap_err("failed to build outside slot mesh url")?;
    let peer_key = base64::engine::general_purpose::STANDARD.encode(outside_public.public_key);
    mesh_url
        .query_pairs_mut()
        .append_pair("peer_id", &outside_public.id)
        .append_pair("peer_key", &peer_key)
        .append_pair("route_id", route_id)
        .append_pair("capability", slot_name);
    Ok(mesh_url.to_string())
}

pub(super) fn outside_proxy_mesh_listen_addr(
    context: &RunOutsideProxyContext,
    slot_bindings: &[(String, String)],
    port: u16,
) -> Result<SocketAddr> {
    let needs_host_wide_listener = slot_bindings.iter().any(|(slot_name, _)| {
        context
            .slots
            .get(slot_name)
            .expect("outside proxy slot should exist after validation")
            .consumer_sites
            .iter()
            .any(|site_id| {
                let consumer_kind = context
                    .sites
                    .get(site_id)
                    .expect("consumer site should exist")
                    .receipt
                    .kind;
                consumer_needs_host_wide_listener(consumer_kind)
            })
    });
    Ok(host_proxy_bind_addr(needs_host_wide_listener, port))
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
