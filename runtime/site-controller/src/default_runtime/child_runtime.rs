use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct SiteControllerRuntimeState {
    pub(super) schema: String,
    pub(super) version: u32,
    pub(super) run_id: String,
    pub(super) site_id: String,
    pub(super) kind: SiteKind,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) children: BTreeMap<u64, SiteControllerRuntimeChildRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct SiteControllerRuntimeChildRecord {
    pub(super) child_id: u64,
    pub(super) artifact_root: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) assigned_components: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) proxy_exports: BTreeMap<String, DynamicProxyExportRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) direct_inputs: Vec<DynamicInputDirectRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) routed_inputs: Vec<DynamicInputRouteRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) process_pid: Option<u32>,
    pub(super) published: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct DynamicComposeChildMetadata {
    pub(super) schema: String,
    pub(super) version: u32,
    pub(super) services: Vec<String>,
    pub(super) readiness_services: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct StoredRouteOverlayPayload {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) peers: Vec<MeshPeer>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) inbound_routes: Vec<InboundRoute>,
}

pub(crate) struct BridgeProxyHandle {
    pub(crate) child: Child,
    pub(crate) listen: SocketAddr,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct BridgeProxyKey {
    pub(crate) provider_output_dir: String,
    pub(crate) export_name: String,
    pub(crate) consumer_kind: SiteKind,
}

#[derive(Clone, Default)]
pub struct DefaultSiteControllerRuntime {
    bridge_proxies: Arc<AsyncMutex<BTreeMap<BridgeProxyKey, BridgeProxyHandle>>>,
}

pub(crate) fn default_site_controller_runtime() -> SharedSiteControllerRuntime {
    Arc::new(DefaultSiteControllerRuntime::default())
}

impl SiteControllerRuntime for DefaultSiteControllerRuntime {
    fn cleanup<'a>(&'a self) -> SiteControllerRuntimeFuture<'a, ()> {
        Box::pin(async move {
            let mut bridge_proxies = {
                let mut guard = self.bridge_proxies.lock().await;
                std::mem::take(&mut *guard)
            };
            stop_bridge_proxies(&mut bridge_proxies).await
        })
    }

    fn resolve_link_external_url<'a>(
        &'a self,
        provider: &'a LaunchedSite,
        provider_output_dir: &'a Path,
        link: &'a RunLink,
        consumer_kind: SiteKind,
        run_root: &'a Path,
    ) -> SiteControllerRuntimeFuture<'a, String> {
        Box::pin(async move {
            let mut bridge_proxies = self.bridge_proxies.lock().await;
            resolve_link_external_url_for_output(
                provider,
                provider_output_dir,
                link,
                consumer_kind,
                run_root,
                &mut bridge_proxies,
            )
            .await
        })
    }

    fn prepare_child<'a>(
        &'a self,
        plan: &'a SiteControllerPlan,
        state: FrameworkControlState,
        child: LiveChildRecord,
    ) -> SiteControllerRuntimeFuture<'a, ()> {
        Box::pin(async move { site_controller_prepare_child(plan, state, child).await })
    }

    fn publish_child<'a>(
        &'a self,
        plan: &'a SiteControllerPlan,
        state: FrameworkControlState,
        child: LiveChildRecord,
    ) -> SiteControllerRuntimeFuture<'a, ()> {
        Box::pin(async move { site_controller_publish_child(plan, state, child).await })
    }

    fn rollback_child<'a>(
        &'a self,
        plan: &'a SiteControllerPlan,
        child_id: u64,
    ) -> SiteControllerRuntimeFuture<'a, ()> {
        Box::pin(async move { site_controller_rollback_child(plan, child_id).await })
    }

    fn destroy_child<'a>(
        &'a self,
        plan: &'a SiteControllerPlan,
        state: FrameworkControlState,
        child: LiveChildRecord,
    ) -> SiteControllerRuntimeFuture<'a, ()> {
        Box::pin(async move { site_controller_destroy_child(plan, state, child).await })
    }

    fn collect_live_component_runtime_metadata(
        &self,
        plan: &SiteControllerRuntimePlan,
    ) -> Result<BTreeMap<String, LiveComponentRuntimeMetadata>> {
        collect_live_component_runtime_metadata(plan)
    }

    fn load_live_site_router_mesh_config(
        &self,
        plan: &SiteControllerRuntimePlan,
    ) -> Result<MeshConfigPublic> {
        load_live_site_router_mesh_config(plan)
    }

    fn router_mesh_addr_for_consumer(
        &self,
        provider_kind: SiteKind,
        consumer_kind: SiteKind,
        router_mesh_addr: &str,
    ) -> Result<String> {
        router_mesh_addr_for_consumer(provider_kind, consumer_kind, router_mesh_addr)
    }

    fn update_desired_overlay_for_consumer(
        &self,
        site_state_root: &Path,
        overlay_id: &str,
        overlay: DesiredExternalSlotOverlay,
    ) -> Result<()> {
        update_desired_overlay_for_consumer(site_state_root, overlay_id, overlay)
    }

    fn update_desired_overlay_for_provider(
        &self,
        site_state_root: &Path,
        overlay_id: &str,
        overlay: DesiredExportPeerOverlay,
    ) -> Result<()> {
        update_desired_overlay_for_provider(site_state_root, overlay_id, overlay)
    }

    fn clear_desired_overlay_for_consumer(
        &self,
        site_state_root: &Path,
        overlay_id: &str,
    ) -> Result<()> {
        clear_desired_overlay_for_consumer(site_state_root, overlay_id)
    }

    fn clear_desired_overlay_for_provider(
        &self,
        site_state_root: &Path,
        overlay_id: &str,
    ) -> Result<()> {
        clear_desired_overlay_for_provider(site_state_root, overlay_id)
    }
}

pub(crate) async fn stop_bridge_proxies(
    bridge_proxies: &mut BTreeMap<BridgeProxyKey, BridgeProxyHandle>,
) -> Result<()> {
    for bridge in bridge_proxies.values_mut() {
        stop_child(&mut bridge.child).await?;
    }
    bridge_proxies.clear();
    Ok(())
}

pub(super) fn build_site_controller_runtime_app(
    plan: SiteControllerRuntimePlan,
) -> Result<SiteControllerRuntimeApp> {
    let state_path = site_controller_runtime_state_path(Path::new(&plan.site_state_root));
    let initial_state = if state_path.is_file() {
        read_json(&state_path, "site controller runtime state")?
    } else {
        let state = SiteControllerRuntimeState {
            schema: SITE_CONTROLLER_RUNTIME_STATE_SCHEMA.to_string(),
            version: SITE_CONTROLLER_RUNTIME_STATE_VERSION,
            run_id: plan.run_id.clone(),
            site_id: plan.site_id.clone(),
            kind: plan.kind,
            children: BTreeMap::new(),
        };
        write_json(&state_path, &state)?;
        state
    };
    Ok(SiteControllerRuntimeApp {
        plan,
        state_path,
        state: Arc::new(AsyncMutex::new(initial_state)),
    })
}

pub(crate) async fn site_controller_prepare_child(
    plan: &SiteControllerPlan,
    state: FrameworkControlState,
    child: LiveChildRecord,
) -> Result<()> {
    let app = build_site_controller_runtime_app(
        crate::runtime_api::site_controller_runtime_plan_from_controller_plan(plan),
    )?;
    site_controller_runtime_prepare_child(&app, &state, &child).await
}

pub(crate) async fn site_controller_publish_child(
    plan: &SiteControllerPlan,
    state: FrameworkControlState,
    child: LiveChildRecord,
) -> Result<()> {
    let app = build_site_controller_runtime_app(
        crate::runtime_api::site_controller_runtime_plan_from_controller_plan(plan),
    )?;
    site_controller_runtime_publish_child(&app, &state, &child).await
}

pub(crate) async fn site_controller_rollback_child(
    plan: &SiteControllerPlan,
    child_id: u64,
) -> Result<()> {
    let app = build_site_controller_runtime_app(
        crate::runtime_api::site_controller_runtime_plan_from_controller_plan(plan),
    )?;
    site_controller_runtime_rollback_child(&app, child_id).await
}

pub(crate) async fn site_controller_destroy_child(
    plan: &SiteControllerPlan,
    state: FrameworkControlState,
    child: LiveChildRecord,
) -> Result<()> {
    let app = build_site_controller_runtime_app(
        crate::runtime_api::site_controller_runtime_plan_from_controller_plan(plan),
    )?;
    site_controller_runtime_destroy_child(&app, &state, &child).await
}

#[derive(Clone)]
pub(super) struct SiteControllerRuntimeApp {
    pub(super) plan: SiteControllerRuntimePlan,
    pub(super) state_path: PathBuf,
    pub(super) state: Arc<AsyncMutex<SiteControllerRuntimeState>>,
}

fn local_child_runtime_spec(
    plan: &SiteControllerRuntimePlan,
    state: &FrameworkControlState,
    child: &LiveChildRecord,
) -> Result<LocalChildRuntimeSpec> {
    let site_id = child_runtime_site_id(child).map_err(|err| miette::miette!(err.message))?;
    if site_id != plan.site_id {
        return Err(miette::miette!(
            "dynamic child `{}` targeted site `{site_id}` but runtime plan belongs to site `{}`",
            child.name,
            plan.site_id
        ));
    }
    build_local_child_runtime_spec(state, child, &site_id)
        .map_err(|err| miette::miette!(err.message))
}

pub(super) fn site_controller_runtime_state_path(site_state_root: &Path) -> PathBuf {
    site_state_root.join("site-controller-runtime-state.json")
}

pub(super) fn site_controller_runtime_child_root(
    plan: &SiteControllerRuntimePlan,
    child_id: u64,
) -> PathBuf {
    Path::new(&plan.site_state_root)
        .join("framework-component")
        .join("children")
        .join(child_id.to_string())
}

pub(super) fn site_controller_runtime_child_artifact_root(
    plan: &SiteControllerRuntimePlan,
    child_id: u64,
) -> PathBuf {
    site_controller_runtime_child_root(plan, child_id).join("artifact")
}

pub(super) fn site_controller_runtime_child_runtime_root(
    plan: &SiteControllerRuntimePlan,
    child_id: u64,
) -> PathBuf {
    site_controller_runtime_child_root(plan, child_id).join("runtime")
}

pub(super) fn site_controller_runtime_child_storage_root(
    plan: &SiteControllerRuntimePlan,
    child_id: u64,
) -> PathBuf {
    site_controller_runtime_child_root(plan, child_id).join("storage")
}

pub(super) fn site_controller_runtime_child_peer_ports_path(
    plan: &SiteControllerRuntimePlan,
    child_id: u64,
) -> PathBuf {
    site_controller_runtime_child_root(plan, child_id).join("existing-peer-ports.json")
}

pub(super) fn site_controller_runtime_child_peer_identities_path(
    plan: &SiteControllerRuntimePlan,
    child_id: u64,
) -> PathBuf {
    site_controller_runtime_child_root(plan, child_id).join("existing-peer-identities.json")
}

pub(super) fn dynamic_compose_child_metadata_path(artifact_root: &Path) -> PathBuf {
    artifact_root.join(".amber").join("compose-child.json")
}

pub(super) fn dynamic_route_overlay_path(artifact_root: &Path) -> PathBuf {
    artifact_root
        .join(".amber")
        .join(DYNAMIC_ROUTE_OVERLAY_FILENAME)
}

pub(super) fn write_dynamic_route_overlay_payload(
    artifact_root: &Path,
    payload: &StoredRouteOverlayPayload,
) -> Result<()> {
    let path = dynamic_route_overlay_path(artifact_root);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to create {}", parent.display()))?;
    }
    write_json(&path, payload)
}

fn dynamic_proxy_exports_path(artifact_root: &Path) -> PathBuf {
    artifact_root
        .join(".amber")
        .join(DYNAMIC_PROXY_EXPORTS_FILENAME)
}

pub(super) fn write_dynamic_proxy_exports_metadata(
    artifact_root: &Path,
    proxy_exports: &BTreeMap<String, DynamicProxyExportRecord>,
) -> Result<()> {
    if proxy_exports.is_empty() {
        return Ok(());
    }
    let path = dynamic_proxy_exports_path(artifact_root);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to create {}", parent.display()))?;
    }
    write_json(&path, proxy_exports)
}

pub(super) fn load_dynamic_proxy_exports_metadata(
    artifact_root: &Path,
) -> Result<BTreeMap<String, DynamicProxyExportRecord>> {
    let path = dynamic_proxy_exports_path(artifact_root);
    if !path.is_file() {
        return Ok(BTreeMap::new());
    }
    read_json(&path, "dynamic proxy exports")
}

pub fn cleanup_dynamic_site_children(site_state_root: &Path, kind: SiteKind) -> Result<()> {
    let state_path = site_controller_runtime_state_path(site_state_root);
    if !state_path.is_file() {
        return Ok(());
    }
    let mut state: SiteControllerRuntimeState =
        read_json(&state_path, "site controller runtime state")?;
    let compose_supervisor_plan = matches!(kind, SiteKind::Compose)
        .then(|| {
            read_json::<SiteSupervisorPlan>(
                &site_supervisor_plan_path(site_state_root),
                "site supervisor plan",
            )
        })
        .transpose()?;
    for child in state.children.values() {
        if let Some(plan) = compose_supervisor_plan.as_ref() {
            cleanup_dynamic_compose_child(plan, child)?;
        }
        if let Some(pid) = child.process_pid {
            terminate_pid(pid, site_ready_timeout_for_kind(kind))?;
        }
        remove_dir_if_exists(
            &crate::runtime_api::site_controller_runtime_child_root_for_site(
                site_state_root,
                child.child_id,
            ),
        )?;
    }
    if state.children.is_empty() {
        return Ok(());
    }
    state.children.clear();
    write_json(&state_path, &state)
}

fn cleanup_dynamic_compose_child(
    plan: &SiteSupervisorPlan,
    child: &SiteControllerRuntimeChildRecord,
) -> Result<()> {
    let artifact_root = Path::new(&child.artifact_root);
    if !dynamic_compose_child_metadata_path(artifact_root).is_file() {
        return Ok(());
    }
    let compose_project = plan.compose_project.as_deref().ok_or_else(|| {
        miette::miette!(
            "compose site `{}` is missing its compose project name",
            plan.site_id
        )
    })?;
    let status = compose_command(Some(compose_project), artifact_root)
        .envs(plan.launch_env.clone())
        .arg("down")
        .arg("-v")
        .status()
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to clean up dynamic compose child for site `{}`",
                plan.site_id
            )
        })?;
    if !status.success() {
        return Err(miette::miette!(
            "dynamic compose child cleanup on site `{}` failed with status {status}",
            plan.site_id
        ));
    }
    Ok(())
}

pub(super) async fn site_controller_runtime_prepare_child(
    app: &SiteControllerRuntimeApp,
    state: &FrameworkControlState,
    child: &LiveChildRecord,
) -> Result<()> {
    let runtime_spec = local_child_runtime_spec(&app.plan, state, child)?;
    let artifact_root = site_controller_runtime_child_artifact_root(&app.plan, child.child_id);
    let published_children = {
        let state = app.state.lock().await;
        state
            .children
            .values()
            .filter(|child| child.published)
            .cloned()
            .collect::<Vec<_>>()
    };
    let live_components = if runtime_spec.direct_inputs.is_empty() {
        BTreeMap::new()
    } else {
        collect_live_component_runtime_metadata(&app.plan)?
    };
    replace_artifact_snapshot(&artifact_root, &runtime_spec.child_artifact_files)?;
    project_dynamic_child_mesh_scope(&artifact_root, Some(&app.plan.mesh_scope))?;
    if app.plan.kind == SiteKind::Kubernetes {
        let _ = prepare_kubernetes_artifact_namespace(
            &app.plan.run_id,
            &app.plan.site_id,
            &artifact_root,
        )?;
    }
    patch_site_artifacts(
        &artifact_root,
        &app.plan.run_id,
        &app.plan.site_id,
        app.plan.kind,
        &app.plan.launch_env,
        app.plan.observability_endpoint.as_deref(),
    )?;
    match app.plan.kind {
        SiteKind::Direct => {
            filter_direct_stage_plan(&artifact_root, &runtime_spec.component_ids)?;
            ensure_dynamic_proxy_export_component_routes_in_artifact(
                &artifact_root,
                &runtime_spec.proxy_exports,
                &app.plan.router_identity_id,
            )?;
            rewrite_dynamic_direct_inputs_in_artifact(
                &artifact_root,
                &runtime_spec.direct_inputs,
                &live_components,
            )?;
            rewrite_dynamic_routed_inputs_in_artifact(
                &artifact_root,
                &runtime_spec.routed_inputs,
                app.plan.kind,
                &app.plan.router_identity_id,
                app.plan.router_mesh_port,
            )?;
            write_direct_vm_startup_route_overlay_payload(
                &artifact_root,
                "direct",
                &runtime_spec.routed_inputs,
                &overlay_peer_addr_map_from_ports(&local_direct_peer_ports_for_children(
                    &app.plan,
                    &published_children,
                )?),
                &local_direct_peer_identities_for_children(&app.plan, &published_children)?,
            )?;
        }
        SiteKind::Vm => {
            filter_vm_stage_plan(&artifact_root, &runtime_spec.component_ids)?;
            ensure_dynamic_proxy_export_component_routes_in_artifact(
                &artifact_root,
                &runtime_spec.proxy_exports,
                &app.plan.router_identity_id,
            )?;
            rewrite_dynamic_direct_inputs_in_artifact(
                &artifact_root,
                &runtime_spec.direct_inputs,
                &live_components,
            )?;
            rewrite_dynamic_routed_inputs_in_artifact(
                &artifact_root,
                &runtime_spec.routed_inputs,
                app.plan.kind,
                &app.plan.router_identity_id,
                app.plan.router_mesh_port,
            )?;
            write_direct_vm_startup_route_overlay_payload(
                &artifact_root,
                "vm",
                &runtime_spec.routed_inputs,
                &overlay_peer_addr_map_from_ports(&local_vm_peer_ports_for_children(
                    &app.plan,
                    &published_children,
                )?),
                &local_vm_peer_identities_for_children(&app.plan, &published_children)?,
            )?;
        }
        SiteKind::Compose => {
            let existing_peer_identities =
                local_compose_peer_identities(&app.plan, &published_children)?;
            prepare_dynamic_compose_child_artifact(
                &app.plan,
                &runtime_spec,
                &artifact_root,
                &published_children,
                &existing_peer_identities,
                &live_components,
            )?
        }
        SiteKind::Kubernetes => {
            let existing_peer_identities =
                local_kubernetes_peer_identities(&app.plan, &published_children)?;
            prepare_dynamic_kubernetes_child_artifact(
                &app.plan,
                &runtime_spec,
                &artifact_root,
                &existing_peer_identities,
                &live_components,
            )?
        }
    }
    write_dynamic_proxy_exports_metadata(&artifact_root, &runtime_spec.proxy_exports)?;
    rewrite_dynamic_proxy_metadata(&artifact_root, &runtime_spec.proxy_exports, app.plan.kind)?;
    if app.plan.kind == SiteKind::Compose
        && let Some(compose_project) = app.plan.compose_project.as_deref()
    {
        rewrite_dynamic_compose_proxy_metadata(&artifact_root, compose_project)?;
    }
    let mut state = app.state.lock().await;
    state.children.insert(
        child.child_id,
        SiteControllerRuntimeChildRecord {
            child_id: child.child_id,
            artifact_root: artifact_root.display().to_string(),
            assigned_components: runtime_spec.assigned_components.clone(),
            proxy_exports: runtime_spec.proxy_exports.clone(),
            direct_inputs: runtime_spec.direct_inputs.clone(),
            routed_inputs: runtime_spec.routed_inputs.clone(),
            process_pid: None,
            published: false,
        },
    );
    write_json(&app.state_path, &*state)
}

pub(super) async fn site_controller_runtime_publish_child(
    app: &SiteControllerRuntimeApp,
    state: &FrameworkControlState,
    child: &LiveChildRecord,
) -> Result<()> {
    let runtime_spec = local_child_runtime_spec(&app.plan, state, child)?;
    let child_id = child.child_id;
    let (child, published_children) = {
        let state = app.state.lock().await;
        let child = state.children.get(&child_id).cloned().ok_or_else(|| {
            miette::miette!("site controller runtime child {child_id} is not prepared")
        })?;
        let published_children = state
            .children
            .values()
            .filter(|child| child.published)
            .cloned()
            .collect::<Vec<_>>();
        (child, published_children)
    };
    if child.published {
        return Ok(());
    }

    match app.plan.kind {
        SiteKind::Direct => {
            let state = app.state.lock().await;
            let existing_peer_ports = local_direct_peer_ports(&app.plan, &state)?;
            let existing_peer_identities = local_direct_peer_identities(&app.plan, &state)?;
            drop(state);
            write_json(
                &site_controller_runtime_child_peer_ports_path(&app.plan, child_id),
                &existing_peer_ports,
            )?;
            write_json(
                &site_controller_runtime_child_peer_identities_path(&app.plan, child_id),
                &existing_peer_identities,
            )?;
            project_dynamic_child_mesh_scope(
                Path::new(&child.artifact_root),
                existing_peer_identities
                    .get(&app.plan.router_identity_id)
                    .and_then(|identity| identity.mesh_scope.as_deref()),
            )?;
            if dynamic_route_overlay_path(Path::new(&child.artifact_root)).is_file() {
                apply_dynamic_site_router_overlay(&app.plan, &child).await?;
            }
            let runtime_root = site_controller_runtime_child_runtime_root(&app.plan, child_id);
            let storage_root = site_controller_runtime_child_storage_root(&app.plan, child_id);
            let child_root = site_controller_runtime_child_root(&app.plan, child_id);
            fs::create_dir_all(&runtime_root)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to create {}", runtime_root.display()))?;
            fs::create_dir_all(&storage_root)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to create {}", storage_root.display()))?;
            let process = spawn_detached_child(&child_root, &child_root.join("site.log"), |cmd| {
                cmd.arg("run-direct-init")
                    .arg("--plan")
                    .arg(Path::new(&child.artifact_root).join("direct-plan.json"))
                    .arg("--storage-root")
                    .arg(&storage_root)
                    .arg("--runtime-root")
                    .arg(&runtime_root)
                    .arg("--existing-peer-ports")
                    .arg(site_controller_runtime_child_peer_ports_path(
                        &app.plan, child_id,
                    ))
                    .arg("--existing-peer-identities")
                    .arg(site_controller_runtime_child_peer_identities_path(
                        &app.plan, child_id,
                    ))
                    .arg("--skip-router");
            })?;
            {
                let mut state = app.state.lock().await;
                let record = state
                    .children
                    .get_mut(&child_id)
                    .expect("prepared child should remain present");
                record.process_pid = Some(process.id());
                write_json(&app.state_path, &*state)?;
            }
            wait_for_detached_child_runtime_state(
                process.id(),
                &direct_runtime_state_path(Path::new(&child.artifact_root)),
                site_ready_timeout_for_kind(SiteKind::Direct),
                &child_root.join("site.log"),
            )
            .await?;
            let mut live_children = published_children.clone();
            live_children.push(child.clone());
            let live_peer_ports = overlay_peer_addr_map_from_ports(
                &local_direct_peer_ports_for_children(&app.plan, &live_children)?,
            );
            let live_peer_identities =
                local_direct_peer_identities_for_children(&app.plan, &live_children)?;
            write_direct_vm_live_route_overlay_payload(
                Path::new(&child.artifact_root),
                &child.assigned_components,
                &child.proxy_exports,
                &child.routed_inputs,
                &live_peer_ports,
                &live_peer_identities,
            )?;
            apply_dynamic_site_router_overlay(&app.plan, &child).await?;
            let mut state = app.state.lock().await;
            {
                let record = state
                    .children
                    .get_mut(&child_id)
                    .expect("prepared child should remain present");
                record.process_pid = Some(process.id());
                record.published = true;
            }
            write_json(&app.state_path, &*state)?;
            drop(state);
            project_dynamic_direct_router_surface(&app.plan, &child)?;
            reconcile_dynamic_site_router_overlays(app).await?;
            reconcile_dynamic_direct_input_overlays(app).await?;
            reconcile_site_proxy_metadata(
                Path::new(&app.plan.artifact_dir),
                &runtime_spec.site_artifact_files,
            )?;
        }
        SiteKind::Vm => {
            let state = app.state.lock().await;
            let existing_peer_ports = local_vm_peer_ports(&app.plan, &state)?;
            let existing_peer_identities = local_vm_peer_identities(&app.plan, &state)?;
            drop(state);
            write_json(
                &site_controller_runtime_child_peer_ports_path(&app.plan, child_id),
                &existing_peer_ports,
            )?;
            write_json(
                &site_controller_runtime_child_peer_identities_path(&app.plan, child_id),
                &existing_peer_identities,
            )?;
            project_dynamic_child_mesh_scope(
                Path::new(&child.artifact_root),
                existing_peer_identities
                    .get(&app.plan.router_identity_id)
                    .and_then(|identity| identity.mesh_scope.as_deref()),
            )?;
            if dynamic_route_overlay_path(Path::new(&child.artifact_root)).is_file() {
                apply_dynamic_site_router_overlay(&app.plan, &child).await?;
            }
            let runtime_root = site_controller_runtime_child_runtime_root(&app.plan, child_id);
            let storage_root = site_controller_runtime_child_storage_root(&app.plan, child_id);
            let child_root = site_controller_runtime_child_root(&app.plan, child_id);
            fs::create_dir_all(&runtime_root)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to create {}", runtime_root.display()))?;
            fs::create_dir_all(&storage_root)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to create {}", storage_root.display()))?;
            let process = spawn_detached_child(&child_root, &child_root.join("site.log"), |cmd| {
                cmd.arg("run-vm-init")
                    .arg("--plan")
                    .arg(Path::new(&child.artifact_root).join("vm-plan.json"))
                    .arg("--storage-root")
                    .arg(&storage_root)
                    .arg("--runtime-root")
                    .arg(&runtime_root)
                    .arg("--existing-peer-ports")
                    .arg(site_controller_runtime_child_peer_ports_path(
                        &app.plan, child_id,
                    ))
                    .arg("--existing-peer-identities")
                    .arg(site_controller_runtime_child_peer_identities_path(
                        &app.plan, child_id,
                    ))
                    .arg("--skip-router");
            })?;
            {
                let mut state = app.state.lock().await;
                let record = state
                    .children
                    .get_mut(&child_id)
                    .expect("prepared child should remain present");
                record.process_pid = Some(process.id());
                write_json(&app.state_path, &*state)?;
            }
            wait_for_detached_child_runtime_state(
                process.id(),
                &Path::new(&child.artifact_root)
                    .join(".amber")
                    .join("vm-runtime.json"),
                vm_endpoint_forward_ready_timeout(),
                &child_root.join("site.log"),
            )
            .await?;
            wait_for_detached_vm_child_endpoints_ready(
                process.id(),
                Path::new(&child.artifact_root),
                &runtime_root,
                vm_endpoint_forward_ready_timeout(),
                &child_root.join("site.log"),
            )?;
            let mut live_children = published_children.clone();
            live_children.push(child.clone());
            let live_peer_ports = overlay_peer_addr_map_from_ports(
                &local_vm_peer_ports_for_children(&app.plan, &live_children)?,
            );
            let live_peer_identities =
                local_vm_peer_identities_for_children(&app.plan, &live_children)?;
            write_direct_vm_live_route_overlay_payload(
                Path::new(&child.artifact_root),
                &child.assigned_components,
                &child.proxy_exports,
                &child.routed_inputs,
                &live_peer_ports,
                &live_peer_identities,
            )?;
            apply_dynamic_site_router_overlay(&app.plan, &child).await?;
            let mut state = app.state.lock().await;
            {
                let record = state
                    .children
                    .get_mut(&child_id)
                    .expect("prepared child should remain present");
                record.process_pid = Some(process.id());
                record.published = true;
            }
            write_json(&app.state_path, &*state)?;
            drop(state);
            project_dynamic_vm_router_surface(&app.plan, &child)?;
            reconcile_dynamic_site_router_overlays(app).await?;
            reconcile_dynamic_direct_input_overlays(app).await?;
            reconcile_site_proxy_metadata(
                Path::new(&app.plan.artifact_dir),
                &runtime_spec.site_artifact_files,
            )?;
        }
        SiteKind::Compose => {
            let mut issuer_children = published_children.clone();
            issuer_children.push(child.clone());
            reconcile_dynamic_site_router_overlays_for_children(
                app,
                &published_children,
                &issuer_children,
            )
            .await?;
            apply_dynamic_site_router_overlay(&app.plan, &child).await?;
            let metadata = load_dynamic_compose_child_metadata(Path::new(&child.artifact_root))?;
            let compose_project = app.plan.compose_project.as_deref().ok_or_else(|| {
                miette::miette!(
                    "compose site `{}` is missing its compose project name",
                    app.plan.site_id
                )
            })?;
            let (sidecar_services, workload_services): (Vec<_>, Vec<_>) = metadata
                .services
                .iter()
                .cloned()
                .partition(|service| is_compose_component_sidecar_service(service));
            if !sidecar_services.is_empty() {
                let status =
                    compose_command(Some(compose_project), Path::new(&child.artifact_root))
                        .envs(app.plan.launch_env.clone())
                        .arg("up")
                        .arg("-d")
                        .args(&sidecar_services)
                        .status()
                        .into_diagnostic()
                        .wrap_err_with(|| {
                            format!(
                                "failed to publish compose child sidecars on site `{}`",
                                app.plan.site_id
                            )
                        })?;
                if !status.success() {
                    return Err(miette::miette!(
                        "compose child sidecar publish on site `{}` failed with status {status}",
                        app.plan.site_id
                    ));
                }
                wait_for_compose_services_running(
                    compose_project,
                    Path::new(&child.artifact_root),
                    &sidecar_services,
                    site_ready_timeout_for_kind(SiteKind::Compose),
                )
                .await?;
            }
            if !workload_services.is_empty() {
                let status =
                    compose_command(Some(compose_project), Path::new(&child.artifact_root))
                        .envs(app.plan.launch_env.clone())
                        .arg("up")
                        .arg("-d")
                        .args(&workload_services)
                        .status()
                        .into_diagnostic()
                        .wrap_err_with(|| {
                            format!(
                                "failed to publish compose child workloads on site `{}`",
                                app.plan.site_id
                            )
                        })?;
                if !status.success() {
                    return Err(miette::miette!(
                        "compose child workload publish on site `{}` failed with status {status}",
                        app.plan.site_id
                    ));
                }
            }
            wait_for_compose_services_running(
                compose_project,
                Path::new(&child.artifact_root),
                &metadata.readiness_services,
                site_ready_timeout_for_kind(SiteKind::Compose),
            )
            .await?;
            let mut state = app.state.lock().await;
            let record = state
                .children
                .get_mut(&child_id)
                .expect("prepared child should remain present");
            record.published = true;
            write_json(&app.state_path, &*state)?;
            drop(state);
            reconcile_dynamic_site_router_overlays(app).await?;
            reconcile_dynamic_direct_input_overlays(app).await?;
        }
        SiteKind::Kubernetes => {
            let artifact_root = Path::new(&child.artifact_root);
            let supervisor_plan = prepare_kubernetes_artifact_for_apply(&app.plan, artifact_root)?;
            ensure_kubernetes_namespace(&supervisor_plan)?;
            let status = kubectl_command(app.plan.context.as_deref())
                .current_dir(artifact_root)
                .arg("apply")
                .arg("-k")
                .arg(".")
                .status()
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!("failed to publish kubernetes site `{}`", app.plan.site_id)
                })?;
            if !status.success() {
                return Err(miette::miette!(
                    "kubernetes site `{}` publish failed with status {status}",
                    app.plan.site_id
                ));
            }
            ensure_kubernetes_workloads_ready(&supervisor_plan)?;
            let mut live_children = published_children.clone();
            live_children.push(child.clone());
            let live_peer_identities = local_kubernetes_peer_identities(&app.plan, &live_children)?;
            write_kubernetes_live_route_overlay_payload(
                artifact_root,
                &child.assigned_components,
                &child.proxy_exports,
                &child.routed_inputs,
                &live_peer_identities,
            )?;
            apply_dynamic_site_router_overlay(&app.plan, &child).await?;
            let mut state = app.state.lock().await;
            let record = state
                .children
                .get_mut(&child_id)
                .expect("prepared child should remain present");
            record.published = true;
            write_json(&app.state_path, &*state)?;
            drop(state);
            reconcile_dynamic_site_router_overlays(app).await?;
            reconcile_dynamic_direct_input_overlays(app).await?;
            wait_for_kubernetes_site_router_ready(
                &app.plan,
                site_ready_timeout_for_kind(SiteKind::Kubernetes),
            )
            .await?;
        }
    }

    Ok(())
}

pub(super) async fn site_controller_runtime_rollback_child(
    app: &SiteControllerRuntimeApp,
    child_id: u64,
) -> Result<()> {
    let child = {
        let mut state = app.state.lock().await;
        let removed = state.children.remove(&child_id);
        write_json(&app.state_path, &*state)?;
        removed
    };
    let Some(child) = child else {
        return Ok(());
    };
    if let Some(pid) = child.process_pid {
        terminate_pid(pid, site_ready_timeout_for_kind(app.plan.kind))?;
    }
    remove_dir_if_exists(&site_controller_runtime_child_root(&app.plan, child_id))
}

pub(super) async fn site_controller_runtime_destroy_child(
    app: &SiteControllerRuntimeApp,
    state: &FrameworkControlState,
    child: &LiveChildRecord,
) -> Result<()> {
    let site_id = child_runtime_site_id(child).map_err(|err| miette::miette!(err.message))?;
    let child_id = child.child_id;
    let child = {
        let state = app.state.lock().await;
        state.children.get(&child_id).cloned()
    };
    if let Some(child) = child.as_ref()
        && matches!(
            app.plan.kind,
            SiteKind::Direct | SiteKind::Vm | SiteKind::Compose | SiteKind::Kubernetes
        )
    {
        revoke_dynamic_site_router_overlay(&app.plan, child).await?;
    }
    if let Some(pid) = child.as_ref().and_then(|child| child.process_pid) {
        terminate_pid(pid, site_ready_timeout_for_kind(app.plan.kind))?;
    }

    match app.plan.kind {
        SiteKind::Compose => {
            let child = child.as_ref().ok_or_else(|| {
                miette::miette!("site controller runtime child {child_id} is not prepared")
            })?;
            let metadata = load_dynamic_compose_child_metadata(Path::new(&child.artifact_root))?;
            let compose_project = app.plan.compose_project.as_deref().ok_or_else(|| {
                miette::miette!(
                    "compose site `{}` is missing its compose project name",
                    app.plan.site_id
                )
            })?;
            if !metadata.services.is_empty() {
                let status =
                    compose_command(Some(compose_project), Path::new(&child.artifact_root))
                        .envs(app.plan.launch_env.clone())
                        .arg("rm")
                        .arg("--stop")
                        .arg("--force")
                        .arg("-v")
                        .args(&metadata.services)
                        .status()
                        .into_diagnostic()
                        .wrap_err_with(|| {
                            format!(
                                "failed to destroy compose child on site `{}`",
                                app.plan.site_id
                            )
                        })?;
                if !status.success() {
                    return Err(miette::miette!(
                        "compose child destroy on site `{}` failed with status {status}",
                        app.plan.site_id
                    ));
                }
            }
        }
        SiteKind::Kubernetes => {
            let child = child.as_ref().ok_or_else(|| {
                miette::miette!("site controller runtime child {child_id} is not prepared")
            })?;
            let artifact_root = Path::new(&child.artifact_root);
            let files = read_artifact_snapshot(artifact_root)?;
            let destroy_bundle = project_kubernetes_dynamic_child_destroy_artifact_files(&files)?;
            replace_artifact_snapshot(artifact_root, &destroy_bundle)?;
            let supervisor_plan = prepare_kubernetes_artifact_for_apply(&app.plan, artifact_root)?;
            let workloads = kubernetes_expected_workloads(artifact_root)?;
            let status = kubectl_command(app.plan.context.as_deref())
                .current_dir(artifact_root)
                .arg("delete")
                .arg("-k")
                .arg(".")
                .arg("--ignore-not-found=true")
                .status()
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!(
                        "failed to destroy kubernetes child on site `{}`",
                        app.plan.site_id
                    )
                })?;
            if !status.success() {
                return Err(miette::miette!(
                    "kubernetes child destroy on site `{}` failed with status {status}",
                    app.plan.site_id
                ));
            }
            wait_for_kubernetes_artifact_workloads_deleted(
                app.plan.context.as_deref(),
                supervisor_plan
                    .kubernetes_namespace
                    .as_deref()
                    .expect("kubernetes supervisor plan should include a namespace"),
                &workloads,
                &app.plan.site_id,
            )?;
            wait_for_kubernetes_site_router_ready(
                &app.plan,
                site_ready_timeout_for_kind(SiteKind::Kubernetes),
            )
            .await?;
        }
        SiteKind::Direct | SiteKind::Vm => {
            let site_artifact_files = build_desired_site_artifact_files(state, &site_id)
                .map_err(|err| miette::miette!(err.message))?;
            reconcile_site_proxy_metadata(Path::new(&app.plan.artifact_dir), &site_artifact_files)?;
        }
    }

    let mut state = app.state.lock().await;
    state.children.remove(&child_id);
    write_json(&app.state_path, &*state)?;
    drop(state);
    if matches!(
        app.plan.kind,
        SiteKind::Direct | SiteKind::Vm | SiteKind::Compose | SiteKind::Kubernetes
    ) {
        reconcile_dynamic_site_router_overlays(app).await?;
        reconcile_dynamic_direct_input_overlays(app).await?;
    }
    remove_dir_if_exists(&site_controller_runtime_child_root(&app.plan, child_id))
}
