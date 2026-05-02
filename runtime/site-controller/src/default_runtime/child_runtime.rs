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
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub(super) direct_input_overlay_providers: BTreeSet<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct SiteControllerRuntimeChildRecord {
    pub(super) child_id: u64,
    pub(super) artifact_root: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) assigned_components: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) controller_routes: Vec<InboundRoute>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) proxy_exports: BTreeMap<String, DynamicProxyExportRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) direct_inputs: Vec<DynamicInputDirectRecord>,
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

#[derive(Clone, Default)]
pub struct DefaultSiteControllerRuntime {
    runtime_apps: Arc<std::sync::Mutex<BTreeMap<PathBuf, SiteControllerRuntimeApp>>>,
}

pub(crate) fn default_site_controller_runtime() -> SharedSiteControllerRuntime {
    Arc::new(DefaultSiteControllerRuntime::default())
}

impl SiteControllerRuntime for DefaultSiteControllerRuntime {
    fn cleanup<'a>(&'a self) -> SiteControllerRuntimeFuture<'a, ()> {
        Box::pin(async move {
            self.runtime_apps
                .lock()
                .expect("site controller runtime app cache poisoned")
                .clear();
            Ok(())
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
            resolve_link_external_url_for_output(
                provider,
                provider_output_dir,
                link,
                consumer_kind,
                run_root,
            )
            .await
        })
    }

    fn prepare_child<'a>(
        &'a self,
        plan: &'a SiteControllerPlan,
        state: FrameworkControlState,
        child: LiveChildRecord,
        site_id: &'a str,
    ) -> SiteControllerRuntimeFuture<'a, ()> {
        Box::pin(async move {
            let app = self.runtime_app_for_site(plan, site_id)?;
            site_controller_runtime_prepare_child(&app, &state, &child).await
        })
    }

    fn publish_child<'a>(
        &'a self,
        plan: &'a SiteControllerPlan,
        state: FrameworkControlState,
        child: LiveChildRecord,
        site_id: &'a str,
    ) -> SiteControllerRuntimeFuture<'a, ()> {
        Box::pin(async move {
            let app = self.runtime_app_for_site(plan, site_id)?;
            site_controller_runtime_publish_child(&app, &state, &child).await
        })
    }

    fn rollback_child<'a>(
        &'a self,
        plan: &'a SiteControllerPlan,
        child_id: u64,
        site_id: &'a str,
    ) -> SiteControllerRuntimeFuture<'a, ()> {
        Box::pin(async move {
            let app = self.runtime_app_for_site(plan, site_id)?;
            site_controller_runtime_rollback_child(&app, child_id).await
        })
    }

    fn destroy_child<'a>(
        &'a self,
        plan: &'a SiteControllerPlan,
        state: FrameworkControlState,
        child: LiveChildRecord,
        site_id: &'a str,
    ) -> SiteControllerRuntimeFuture<'a, ()> {
        Box::pin(async move {
            let app = self.runtime_app_for_site(plan, site_id)?;
            site_controller_runtime_destroy_child(&app, &state, &child).await
        })
    }

    fn collect_live_component_runtime_metadata(
        &self,
        plan: &SiteControllerRuntimePlan,
    ) -> Result<BTreeMap<String, LiveComponentRuntimeMetadata>> {
        let _ = self.runtime_app_for_plan(plan)?;
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

    fn router_mesh_addr_for_component_consumer(
        &self,
        provider_kind: SiteKind,
        consumer_kind: SiteKind,
        router_mesh_addr: &str,
    ) -> Result<String> {
        router_mesh_addr_for_component_consumer(provider_kind, consumer_kind, router_mesh_addr)
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

impl DefaultSiteControllerRuntime {
    fn runtime_app_for_site(
        &self,
        controller_plan: &SiteControllerPlan,
        site_id: &str,
    ) -> Result<SiteControllerRuntimeApp> {
        let runtime_plan = runtime_plan_for_site_from_controller_plan(controller_plan, site_id)?;
        self.runtime_app_for_plan(&runtime_plan)
    }

    fn runtime_app_for_plan(
        &self,
        plan: &SiteControllerRuntimePlan,
    ) -> Result<SiteControllerRuntimeApp> {
        let key = Path::new(&plan.site_state_root).to_path_buf();
        let mut runtime_apps = self
            .runtime_apps
            .lock()
            .expect("site controller runtime app cache poisoned");
        if let Some(app) = runtime_apps.get(&key) {
            return Ok(app.clone());
        }
        let app = build_site_controller_runtime_app(plan.clone())?;
        runtime_apps.insert(key, app.clone());
        Ok(app)
    }
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
            direct_input_overlay_providers: BTreeSet::new(),
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

pub(crate) fn runtime_plan_for_site_from_controller_plan(
    controller_plan: &SiteControllerPlan,
    site_id: &str,
) -> Result<SiteControllerRuntimePlan> {
    if site_id == controller_plan.site_id {
        return Ok(site_controller_runtime_plan_from_controller_plan(
            controller_plan,
        ));
    }

    let site_state_root = Path::new(&controller_plan.state_root).join(site_id);
    let supervisor: SiteSupervisorPlan = read_json(
        &site_supervisor_plan_path(&site_state_root),
        "site supervisor plan",
    )?;
    let manager_state_path =
        crate::runtime_api::site_state_path(Path::new(&controller_plan.state_root), site_id);
    let manager = manager_state_path
        .is_file()
        .then(|| read_json::<SiteManagerState>(&manager_state_path, "site manager state"))
        .transpose()?;
    let local_router_control = manager
        .as_ref()
        .and_then(|state| state.router_control.clone())
        .or_else(|| {
            Some(site_runtime_local_router_control(
                supervisor.kind,
                Path::new(&supervisor.artifact_dir),
            ))
        });
    let router_identity_id = manager
        .as_ref()
        .and_then(|state| state.router_identity_id.clone())
        .or_else(|| {
            controller_plan
                .peer_router_identities
                .get(site_id)
                .map(|identity| identity.id.clone())
        })
        .ok_or_else(|| miette::miette!("site `{site_id}` is missing its router identity"))?;
    let router_mesh_port = manager
        .as_ref()
        .and_then(|state| state.router_mesh_addr.as_deref())
        .and_then(|addr| addr.rsplit_once(':'))
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .or(supervisor.router_mesh_port)
        .or(supervisor.port_forward_mesh_port);

    let mut runtime_plan = site_controller_runtime_plan_from_controller_plan(controller_plan);
    runtime_plan.run_id = supervisor.run_id;
    runtime_plan.mesh_scope = supervisor.mesh_scope;
    runtime_plan.run_root = supervisor.run_root;
    runtime_plan.site_id = supervisor.site_id;
    runtime_plan.kind = supervisor.kind;
    runtime_plan.router_identity_id = router_identity_id;
    runtime_plan.local_router_control = local_router_control;
    runtime_plan.artifact_dir = supervisor.artifact_dir;
    runtime_plan.site_state_root = supervisor.site_state_root;
    runtime_plan.storage_root = supervisor.storage_root;
    runtime_plan.runtime_root = supervisor.runtime_root;
    runtime_plan.router_mesh_port = router_mesh_port;
    runtime_plan.compose_project = supervisor.compose_project;
    runtime_plan.kubernetes_namespace = supervisor.kubernetes_namespace;
    runtime_plan.context = supervisor.context;
    runtime_plan.observability_endpoint = supervisor.observability_endpoint;
    runtime_plan.launch_env = supervisor.launch_env;
    Ok(runtime_plan)
}

fn site_runtime_local_router_control(kind: SiteKind, artifact_dir: &Path) -> String {
    match kind {
        SiteKind::Direct => format!(
            "unix://{}",
            super::direct_current_control_socket_path(artifact_dir).display()
        ),
        SiteKind::Vm => format!(
            "unix://{}",
            super::vm_current_control_socket_path(artifact_dir).display()
        ),
        SiteKind::Compose => "unix:///amber/control/router-control.sock".to_string(),
        SiteKind::Kubernetes => "amber-router:24100".to_string(),
    }
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
    build_local_child_runtime_spec(state, child, &plan.site_id)
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
        let child_root = crate::runtime_api::site_controller_runtime_child_root_for_site(
            site_state_root,
            child.child_id,
        );
        remove_dynamic_child_root(kind, &child_root, Some(Path::new(&child.artifact_root)))?;
    }
    if state.children.is_empty() && state.direct_input_overlay_providers.is_empty() {
        return Ok(());
    }
    state.children.clear();
    state.direct_input_overlay_providers.clear();
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

fn compose_cleanup_image_candidates(artifact_root: &Path) -> Result<Vec<String>> {
    let compose_path = artifact_root.join("compose.yaml");
    if !compose_path.is_file() {
        return Ok(vec![
            "docker:28-cli".to_string(),
            "python:3.13-alpine".to_string(),
        ]);
    }

    let document = read_compose_document(&compose_path)?;
    let Some(root) = document.as_mapping() else {
        return Err(miette::miette!(
            "compose file {} is not a YAML mapping",
            compose_path.display()
        ));
    };
    let Some(services) = root
        .get(yaml_string("services"))
        .and_then(serde_yaml::Value::as_mapping)
    else {
        return Err(miette::miette!(
            "compose file {} is missing a services mapping",
            compose_path.display()
        ));
    };

    let mut images = BTreeSet::from([
        "docker:28-cli".to_string(),
        "python:3.13-alpine".to_string(),
    ]);
    for service in services.values() {
        let Some(service_mapping) = service.as_mapping() else {
            continue;
        };
        let Some(image) = service_mapping
            .get(yaml_string("image"))
            .and_then(serde_yaml::Value::as_str)
        else {
            continue;
        };
        images.insert(image.to_string());
    }
    Ok(images.into_iter().collect())
}

fn docker_image_exists_locally(image: &str) -> bool {
    Command::new("docker")
        .arg("image")
        .arg("inspect")
        .arg(image)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn force_remove_dir_if_exists_via_local_container(
    path: &Path,
    artifact_root: &Path,
) -> Result<bool> {
    if !path.exists() {
        return Ok(true);
    }
    let Some(parent) = path.parent() else {
        return Ok(false);
    };

    for image in compose_cleanup_image_candidates(artifact_root)? {
        if !docker_image_exists_locally(&image) {
            continue;
        }
        let status = Command::new("docker")
            .arg("run")
            .arg("--rm")
            .arg("--user")
            .arg("0:0")
            .arg("-v")
            .arg(format!("{}:{}", parent.display(), parent.display()))
            .arg("--entrypoint")
            .arg("rm")
            .arg(&image)
            .arg("-rf")
            .arg(path)
            .status()
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "failed to launch fallback cleanup container `{image}` for {}",
                    path.display()
                )
            })?;
        if status.success() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn remove_dynamic_child_root(
    kind: SiteKind,
    child_root: &Path,
    artifact_root: Option<&Path>,
) -> Result<()> {
    match remove_dir_if_exists(child_root) {
        Ok(()) => Ok(()),
        Err(err) if matches!(kind, SiteKind::Compose) => {
            let Some(artifact_root) = artifact_root else {
                return Err(err.wrap_err(format!(
                    "compose child root {} is missing its artifact directory",
                    child_root.display()
                )));
            };
            if force_remove_dir_if_exists_via_local_container(child_root, artifact_root)? {
                return Ok(());
            }
            Err(err.wrap_err(format!(
                "compose child root {} could not be removed with a local cleanup container",
                child_root.display()
            )))
        }
        Err(err) => Err(err),
    }
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
            controller_routes: runtime_spec.controller_routes.clone(),
            proxy_exports: runtime_spec.proxy_exports.clone(),
            direct_inputs: runtime_spec.direct_inputs.clone(),
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
            let process = spawn_detached_child(
                &child_root,
                &child_root.join("site.log"),
                &app.plan.launch_env,
                |cmd| {
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
                },
            )?;
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
                DetachedChildRuntimeReadiness::DirectReady,
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
            reconcile_dynamic_site_controller_overlay(app).await?;
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
            let process = spawn_detached_child(
                &child_root,
                &child_root.join("site.log"),
                &app.plan.launch_env,
                |cmd| {
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
                },
            )?;
            {
                let mut state = app.state.lock().await;
                let record = state
                    .children
                    .get_mut(&child_id)
                    .expect("prepared child should remain present");
                record.process_pid = Some(process.id());
                write_json(&app.state_path, &*state)?;
            }
            let vm_ready_timeout = vm_endpoint_forward_ready_timeout_for_runtime_plan(&app.plan);
            wait_for_detached_child_runtime_state(
                process.id(),
                &Path::new(&child.artifact_root)
                    .join(".amber")
                    .join("vm-runtime.json"),
                vm_ready_timeout,
                &child_root.join("site.log"),
                DetachedChildRuntimeReadiness::VmMaterialized,
            )
            .await?;
            wait_for_detached_vm_child_endpoints_ready(
                process.id(),
                Path::new(&child.artifact_root),
                &runtime_root,
                vm_ready_timeout,
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
            reconcile_dynamic_site_controller_overlay(app).await?;
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
            {
                let mut state = app.state.lock().await;
                let record = state
                    .children
                    .get_mut(&child_id)
                    .expect("prepared child should remain present");
                // Compose workloads can make one-shot startup calls through their sidecars.
                // Mark the child publishable as soon as its sidecars are up so same-site
                // direct-input grants are reconciled before the workload process starts.
                record.published = true;
                write_json(&app.state_path, &*state)?;
            }
            reconcile_dynamic_site_router_overlays(app).await?;
            reconcile_dynamic_site_controller_overlay(app).await?;
            reconcile_dynamic_direct_input_overlays(app).await?;
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
            reconcile_dynamic_site_controller_overlay(app).await?;
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
    let child_root = site_controller_runtime_child_root(&app.plan, child_id);
    remove_dynamic_child_root(
        app.plan.kind,
        &child_root,
        Some(Path::new(&child.artifact_root)),
    )
}

pub(super) async fn site_controller_runtime_destroy_child(
    app: &SiteControllerRuntimeApp,
    state: &FrameworkControlState,
    child: &LiveChildRecord,
) -> Result<()> {
    let child_id = child.child_id;
    let child = {
        let state = app.state.lock().await;
        state.children.get(&child_id).cloned()
    };
    if child.is_none() {
        let child_root = site_controller_runtime_child_root(&app.plan, child_id);
        let artifact_root = child_root.join("artifact");
        remove_dynamic_child_root(app.plan.kind, &child_root, Some(&artifact_root))?;
        return Ok(());
    }
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
            let site_artifact_files = build_desired_site_artifact_files(state, &app.plan.site_id)
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
        reconcile_dynamic_site_controller_overlay(app).await?;
        reconcile_dynamic_direct_input_overlays(app).await?;
    }
    let child_root = site_controller_runtime_child_root(&app.plan, child_id);
    remove_dynamic_child_root(
        app.plan.kind,
        &child_root,
        child.as_ref().map(|child| Path::new(&child.artifact_root)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compose_cleanup_image_candidates_include_service_images_and_fallbacks() {
        let temp = tempfile::tempdir().expect("temp dir");
        fs::write(
            temp.path().join("compose.yaml"),
            "services:\n  app:\n    image: python:3.13-alpine\n  helper:\n    image: \
             ghcr.io/rdi-foundation/amber-helper:test-tag\n",
        )
        .expect("compose file should write");

        let images = compose_cleanup_image_candidates(temp.path())
            .expect("compose cleanup images should load");

        assert_eq!(
            images,
            vec![
                "docker:28-cli".to_string(),
                "ghcr.io/rdi-foundation/amber-helper:test-tag".to_string(),
                "python:3.13-alpine".to_string(),
            ],
        );
    }

    #[test]
    fn runtime_plan_for_kubernetes_site_uses_port_forward_mesh_runtime_metadata() {
        let temp = tempfile::tempdir().expect("temp dir");
        let state_root = temp.path().join("state");
        let compose_state_root = state_root.join("compose_local");
        let kind_state_root = state_root.join("kind_local");
        let compose_artifact = temp.path().join("artifact").join("compose_local");
        let kind_artifact = temp.path().join("artifact").join("kind_local");
        fs::create_dir_all(&compose_state_root).expect("compose state root");
        fs::create_dir_all(&kind_state_root).expect("kind state root");
        fs::create_dir_all(&compose_artifact).expect("compose artifact");
        fs::create_dir_all(&kind_artifact).expect("kind artifact");

        write_json(
            &site_supervisor_plan_path(&kind_state_root),
            &serde_json::json!({
                "schema": "amber.run.site_supervisor_plan",
                "version": 2,
                "run_id": "test-run",
                "mesh_scope": "test-mesh",
                "run_root": temp.path().join("run").display().to_string(),
                "coordinator_pid": 1u32,
                "site_id": "kind_local",
                "kind": "kubernetes",
                "artifact_dir": kind_artifact.display().to_string(),
                "site_state_root": kind_state_root.display().to_string(),
                "kubernetes_namespace": "amber-test-kind",
                "context": "kind-amber-test",
                "port_forward_mesh_port": 24036u16,
                "port_forward_control_port": 24037u16,
                "launch_env": {"KUBECONFIG": "/tmp/kubeconfig"}
            }),
        )
        .expect("kubernetes supervisor plan should write");
        write_json(
            &crate::runtime_api::site_state_path(&state_root, "kind_local"),
            &serde_json::json!({
                "schema": "amber.run.site_manager_state",
                "version": 1,
                "run_id": "test-run",
                "site_id": "kind_local",
                "kind": "kubernetes",
                "status": "running",
                "artifact_dir": kind_artifact.display().to_string(),
                "supervisor_pid": 1u32,
                "kubernetes_namespace": "amber-test-kind",
                "context": "kind-amber-test",
                "router_control": "127.0.0.1:24037",
                "router_mesh_addr": "127.0.0.1:24036",
                "router_identity_id": "/site/kind_local/router",
                "router_public_key_b64": base64::engine::general_purpose::STANDARD.encode([8u8; 32])
            }),
        )
        .expect("kubernetes manager state should write");

        let controller_plan = SiteControllerPlan {
            schema: "amber.framework_component.site_controller_plan".to_string(),
            version: 1,
            run_id: "test-run".to_string(),
            mesh_scope: "test-mesh".to_string(),
            site_id: "compose_local".to_string(),
            kind: SiteKind::Compose,
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            authority_url: "http://127.0.0.1:0".to_string(),
            router_identity_id: "/site/compose_local/router".to_string(),
            peer_site_router_urls: BTreeMap::new(),
            peer_router_identities: BTreeMap::from([(
                "kind_local".to_string(),
                MeshIdentityPublic {
                    id: "/site/kind_local/router".to_string(),
                    public_key: [8u8; 32],
                    mesh_scope: Some("test-mesh".to_string()),
                },
            )]),
            peer_router_mesh_addrs: BTreeMap::new(),
            local_router_control: Some("unix:///tmp/compose-control.sock".to_string()),
            published_router_mesh_addr: Some("127.0.0.1:24034".to_string()),
            compose_consumer_router_mesh_addr: None,
            kubernetes_consumer_router_mesh_addr: None,
            state_path: compose_state_root
                .join("site-controller-state.json")
                .display()
                .to_string(),
            run_root: temp.path().join("run").display().to_string(),
            state_root: state_root.display().to_string(),
            site_state_root: compose_state_root.display().to_string(),
            artifact_dir: compose_artifact.display().to_string(),
            control_state_auth_token: "test-auth".to_string(),
            dynamic_caps_token_verify_key_b64: String::new(),
            storage_root: None,
            runtime_root: None,
            router_mesh_port: Some(24034),
            compose_project: Some("amber-test-compose".to_string()),
            kubernetes_namespace: None,
            context: None,
            observability_endpoint: None,
            vm_endpoint_forward_ready_timeout_secs: None,
            launch_env: BTreeMap::new(),
        };

        let runtime_plan =
            runtime_plan_for_site_from_controller_plan(&controller_plan, "kind_local")
                .expect("kubernetes runtime plan should derive from the managed site");
        assert_eq!(runtime_plan.site_id, "kind_local");
        assert_eq!(runtime_plan.kind, SiteKind::Kubernetes);
        assert_eq!(
            runtime_plan.artifact_dir,
            kind_artifact.display().to_string()
        );
        assert_eq!(
            runtime_plan.site_state_root,
            kind_state_root.display().to_string()
        );
        assert_eq!(
            runtime_plan.local_router_control.as_deref(),
            Some("127.0.0.1:24037")
        );
        assert_eq!(runtime_plan.router_identity_id, "/site/kind_local/router");
        assert_eq!(runtime_plan.router_mesh_port, Some(24036));
        assert_eq!(
            runtime_plan.kubernetes_namespace.as_deref(),
            Some("amber-test-kind")
        );
        assert_eq!(runtime_plan.context.as_deref(), Some("kind-amber-test"));
        assert_eq!(
            runtime_plan
                .launch_env
                .get("KUBECONFIG")
                .map(String::as_str),
            Some("/tmp/kubeconfig")
        );
    }

    #[test]
    fn runtime_plan_for_vm_site_uses_managed_vm_runtime_metadata() {
        let temp = tempfile::tempdir().expect("temp dir");
        let state_root = temp.path().join("state");
        let direct_state_root = state_root.join("direct_local");
        let vm_state_root = state_root.join("vm_local");
        let direct_artifact = temp.path().join("artifact").join("direct_local");
        let vm_artifact = temp.path().join("artifact").join("vm_local");
        fs::create_dir_all(&direct_state_root).expect("direct state root");
        fs::create_dir_all(&vm_state_root).expect("vm state root");
        fs::create_dir_all(&direct_artifact).expect("direct artifact");
        fs::create_dir_all(&vm_artifact).expect("vm artifact");

        write_json(
            &site_supervisor_plan_path(&vm_state_root),
            &serde_json::json!({
                "schema": "amber.run.site_supervisor_plan",
                "version": 2,
                "run_id": "test-run",
                "mesh_scope": "test-mesh",
                "run_root": temp.path().join("run").display().to_string(),
                "coordinator_pid": 1u32,
                "site_id": "vm_local",
                "kind": "vm",
                "artifact_dir": vm_artifact.display().to_string(),
                "site_state_root": vm_state_root.display().to_string(),
                "storage_root": temp.path().join("storage").join("vm_local").display().to_string(),
                "runtime_root": temp.path().join("runtime").join("vm_local").display().to_string(),
                "router_mesh_port": 24001u16,
                "launch_env": {"AMBER_TEST": "1"}
            }),
        )
        .expect("vm supervisor plan should write");
        write_json(
            &crate::runtime_api::site_state_path(&state_root, "vm_local"),
            &serde_json::json!({
                "schema": "amber.run.site_manager_state",
                "version": 1,
                "run_id": "test-run",
                "site_id": "vm_local",
                "kind": "vm",
                "status": "running",
                "artifact_dir": vm_artifact.display().to_string(),
                "supervisor_pid": 1u32,
                "router_control": "unix:///tmp/vm-control.sock",
                "router_mesh_addr": "127.0.0.1:24001",
                "router_identity_id": "/site/vm_local/router",
                "router_public_key_b64": base64::engine::general_purpose::STANDARD.encode([9u8; 32])
            }),
        )
        .expect("vm manager state should write");

        let controller_plan = SiteControllerPlan {
            schema: "amber.framework_component.site_controller_plan".to_string(),
            version: 1,
            run_id: "test-run".to_string(),
            mesh_scope: "test-mesh".to_string(),
            site_id: "direct_local".to_string(),
            kind: SiteKind::Direct,
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            authority_url: "http://127.0.0.1:0".to_string(),
            router_identity_id: "/site/direct_local/router".to_string(),
            peer_site_router_urls: BTreeMap::new(),
            peer_router_identities: BTreeMap::from([(
                "vm_local".to_string(),
                MeshIdentityPublic {
                    id: "/site/vm_local/router".to_string(),
                    public_key: [9u8; 32],
                    mesh_scope: Some("test-mesh".to_string()),
                },
            )]),
            peer_router_mesh_addrs: BTreeMap::new(),
            local_router_control: Some("unix:///tmp/direct-control.sock".to_string()),
            published_router_mesh_addr: Some("127.0.0.1:24000".to_string()),
            compose_consumer_router_mesh_addr: None,
            kubernetes_consumer_router_mesh_addr: None,
            state_path: direct_state_root
                .join("site-controller-state.json")
                .display()
                .to_string(),
            run_root: temp.path().join("run").display().to_string(),
            state_root: state_root.display().to_string(),
            site_state_root: direct_state_root.display().to_string(),
            artifact_dir: direct_artifact.display().to_string(),
            control_state_auth_token: "test-auth".to_string(),
            dynamic_caps_token_verify_key_b64: String::new(),
            storage_root: Some(
                temp.path()
                    .join("storage")
                    .join("direct_local")
                    .display()
                    .to_string(),
            ),
            runtime_root: Some(
                temp.path()
                    .join("runtime")
                    .join("direct_local")
                    .display()
                    .to_string(),
            ),
            router_mesh_port: Some(24000),
            compose_project: None,
            kubernetes_namespace: None,
            context: None,
            observability_endpoint: None,
            vm_endpoint_forward_ready_timeout_secs: None,
            launch_env: BTreeMap::new(),
        };

        let runtime_plan = runtime_plan_for_site_from_controller_plan(&controller_plan, "vm_local")
            .expect("vm runtime plan should derive from the managed site");
        assert_eq!(runtime_plan.site_id, "vm_local");
        assert_eq!(runtime_plan.kind, SiteKind::Vm);
        assert_eq!(runtime_plan.artifact_dir, vm_artifact.display().to_string());
        assert_eq!(
            runtime_plan.site_state_root,
            vm_state_root.display().to_string()
        );
        assert_eq!(
            runtime_plan.local_router_control.as_deref(),
            Some("unix:///tmp/vm-control.sock")
        );
        assert_eq!(runtime_plan.router_identity_id, "/site/vm_local/router");
        assert_eq!(runtime_plan.router_mesh_port, Some(24001));
        assert_eq!(
            runtime_plan
                .launch_env
                .get("AMBER_TEST")
                .map(String::as_str),
            Some("1")
        );
    }
}
