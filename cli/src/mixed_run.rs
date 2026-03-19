use std::{
    collections::BTreeMap,
    env, fs,
    io::{Read as _, Write as _},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use amber_compiler::run_plan::{RunLink, RunPlan, RunSitePlan, SiteKind};
use amber_manifest::NetworkProtocol;
use amber_mesh::{
    MeshIdentityPublic, MeshProtocol, router_export_route_id,
    telemetry::{SCENARIO_RUN_ID_ENV, SCENARIO_SCOPE_ENV},
};
use amber_proxy::{
    ControlEndpoint, RouterDiscovery, discover_router_for_output, fetch_router_identity,
    register_export_peer_with_retry, register_external_slot_with_retry,
};
use base64::Engine as _;
use miette::{Context as _, IntoDiagnostic as _, Result};
use serde::{Deserialize, Serialize};
use tokio::time::{Instant, sleep};
use url::Url;

use crate::{
    direct_current_control_socket_path, direct_runtime_state_path,
    vm_runtime::{VmRuntimeState, vm_current_control_socket_path},
};

const RECEIPT_SCHEMA: &str = "amber.run.receipt";
const RECEIPT_VERSION: u32 = 2;
const SITE_STATE_SCHEMA: &str = "amber.run.site_state";
const SITE_STATE_VERSION: u32 = 2;
const SITE_PLAN_SCHEMA: &str = "amber.run.site_supervisor_plan";
const SITE_PLAN_VERSION: u32 = 1;
const DESIRED_LINKS_SCHEMA: &str = "amber.run.desired_links";
const DESIRED_LINKS_VERSION: u32 = 1;
const OTLP_SINK_PLAN_SCHEMA: &str = "amber.run.observability_sink";
const OTLP_SINK_PLAN_VERSION: u32 = 1;
const OTELCOL_UPSTREAM_ENV: &str = "AMBER_OTEL_UPSTREAM_OTLP_HTTP_ENDPOINT";
const TEST_WAVE_DELAY_ENV: &str = "AMBER_TEST_MIXED_RUN_AFTER_WAVE_DELAY_MS";

const SITE_READY_TIMEOUT: Duration = Duration::from_secs(120);
const ROUTER_CONTROL_TIMEOUT: Duration = Duration::from_secs(30);
const SUPERVISOR_POLL_INTERVAL: Duration = Duration::from_millis(500);
const RESTART_BACKOFF: Duration = Duration::from_secs(1);
const STITCH_REFRESH_INTERVAL: Duration = Duration::from_secs(2);
const PROCESS_SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(10);
const KUBERNETES_NAMESPACE_READY_TIMEOUT: Duration = Duration::from_secs(60);

const DEFAULT_EXTERNAL_ENV_FILE: &str = "router-external.env";
const DEFAULT_K8S_OTEL_UPSTREAM: &str = "http://host.docker.internal:18890";
const CONTAINER_HOST_ALIAS: &str = "host.docker.internal";

static MANAGER_OBSERVABILITY_ENDPOINT: OnceLock<Mutex<Option<String>>> = OnceLock::new();

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RunReceipt {
    pub(crate) schema: String,
    pub(crate) version: u32,
    pub(crate) run_id: String,
    pub(crate) mesh_scope: String,
    pub(crate) plan_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) source_plan_path: Option<String>,
    pub(crate) run_root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) observability: Option<ObservabilityReceipt>,
    pub(crate) sites: BTreeMap<String, SiteReceipt>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ObservabilityReceipt {
    pub(crate) endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) sink_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) requests_log: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SiteReceipt {
    pub(crate) kind: SiteKind,
    pub(crate) artifact_dir: String,
    pub(crate) supervisor_pid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) process_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) compose_project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) kubernetes_namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) port_forward_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) router_control: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) router_mesh_addr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) router_identity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) router_public_key_b64: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SiteLifecycleStatus {
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SiteManagerState {
    schema: String,
    version: u32,
    run_id: String,
    site_id: String,
    kind: SiteKind,
    status: SiteLifecycleStatus,
    artifact_dir: String,
    supervisor_pid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    process_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    compose_project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kubernetes_namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    port_forward_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    router_control: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    router_mesh_addr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    router_identity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    router_public_key_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SiteSupervisorPlan {
    schema: String,
    version: u32,
    run_id: String,
    mesh_scope: String,
    run_root: String,
    coordinator_pid: u32,
    site_id: String,
    kind: SiteKind,
    artifact_dir: String,
    site_state_root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    storage_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    runtime_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    router_mesh_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    compose_project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kubernetes_namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    port_forward_mesh_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    port_forward_control_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    observability_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    launch_env: BTreeMap<String, String>,
}

struct SupervisorPlanInput<'a> {
    run_root: &'a Path,
    run_id: &'a str,
    mesh_scope: &'a str,
    site_id: &'a str,
    site_plan: &'a RunSitePlan,
    artifact_dir: &'a Path,
    site_state_root: &'a Path,
    observability_endpoint: Option<&'a str>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct DesiredLinkState {
    schema: String,
    version: u32,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    external_slots: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    export_peers: Vec<DesiredExportPeer>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct DesiredExportPeer {
    export_name: String,
    peer_id: String,
    peer_key_b64: String,
    protocol: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ObservabilitySinkPlan {
    schema: String,
    version: u32,
    run_id: String,
    mesh_scope: String,
    run_root: String,
    listen_addr: String,
    advertise_endpoint: String,
    requests_log: String,
}

#[derive(Clone, Debug)]
struct LaunchedSite {
    receipt: SiteReceipt,
    router_control: ControlEndpoint,
    router_identity: MeshIdentityPublic,
    router_addr: SocketAddr,
}

#[derive(Debug, Deserialize)]
struct DirectRuntimeStateView {
    #[serde(default)]
    router_mesh_port: Option<u16>,
}

#[derive(Debug)]
struct SupervisorChild {
    child: Child,
}

#[derive(Debug)]
struct SupervisorRuntime {
    site_process: Option<Child>,
    site_started: bool,
    port_forward: Option<Child>,
    last_start_attempt: Option<Instant>,
    last_stitch_refresh: Option<Instant>,
}

pub(crate) async fn run_run_plan(
    source_plan_path: Option<&Path>,
    run_plan: &RunPlan,
    storage_root_override: Option<&Path>,
    observability: Option<&str>,
) -> Result<RunReceipt> {
    let run_id = new_run_id();
    run_run_plan_with_id(
        source_plan_path,
        run_plan,
        storage_root_override,
        observability,
        &run_id,
    )
    .await
}

pub(crate) async fn run_run_plan_with_id(
    source_plan_path: Option<&Path>,
    run_plan: &RunPlan,
    storage_root_override: Option<&Path>,
    observability: Option<&str>,
    run_id: &str,
) -> Result<RunReceipt> {
    let storage_root = mixed_run_storage_root(storage_root_override)?;
    let run_root = storage_root.join("runs").join(run_id);
    let sites_root = run_root.join("sites");
    let state_root = run_root.join("state");
    fs::create_dir_all(&sites_root)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create run directory {}", sites_root.display()))?;
    fs::create_dir_all(&state_root)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create state directory {}", state_root.display()))?;
    let _coordinator_lock = hold_coordinator_lock(&run_root)?;

    let run_plan_path = run_plan_path(&run_root);
    write_json(&run_plan_path, run_plan)?;

    let observability_receipt =
        start_observability_if_needed(&run_root, run_id, &run_plan.mesh_scope, observability)
            .await?;
    init_manager_telemetry(
        &format!("/run/{run_id}/coordinator"),
        &run_plan.mesh_scope,
        observability_receipt
            .as_ref()
            .map(|value| value.endpoint.as_str()),
    );
    emit_manager_event(
        "amber.run.starting",
        format!("starting mixed-site run {run_id}"),
        &[
            ("amber.run_id", run_id.to_string()),
            ("amber.mesh_scope", run_plan.mesh_scope.clone()),
        ],
    );

    let mut launched_by_site = BTreeMap::<String, LaunchedSite>::new();
    let mut started_site_receipts = BTreeMap::<String, SiteReceipt>::new();
    let mut supervisor_children = BTreeMap::<String, SupervisorChild>::new();
    let test_wave_delay = test_wave_delay()?;

    let result = async {
        for (wave_idx, wave) in run_plan.startup_waves.iter().enumerate() {
            for site_id in wave {
                let site_plan = run_plan
                    .sites
                    .get(site_id)
                    .ok_or_else(|| miette::miette!("run plan is missing site `{site_id}`"))?;
                let artifact_dir = materialize_site_artifacts(&sites_root, site_id, site_plan)?;
                let external_env = external_slot_env_for_site(
                    site_id,
                    site_plan.site.kind,
                    &run_plan.links,
                    &launched_by_site,
                )?;
                patch_site_artifacts(
                    &artifact_dir,
                    site_plan.site.kind,
                    &external_env,
                    observability_receipt
                        .as_ref()
                        .map(|value| value.endpoint.as_str()),
                )?;
                let site_state_root = state_root.join(site_id);
                let launch_env = launch_env(
                    run_id,
                    &run_plan.mesh_scope,
                    site_plan.site.kind,
                    &external_env,
                    observability_receipt
                        .as_ref()
                        .map(|value| value.endpoint.as_str()),
                )?;
                let supervisor_plan = build_supervisor_plan(
                    SupervisorPlanInput {
                        run_root: &run_root,
                        run_id,
                        mesh_scope: &run_plan.mesh_scope,
                        site_id,
                        site_plan,
                        artifact_dir: &artifact_dir,
                        site_state_root: &site_state_root,
                        observability_endpoint: observability_receipt
                            .as_ref()
                            .map(|value| value.endpoint.as_str()),
                    },
                    launch_env,
                )?;
                write_json(
                    &site_supervisor_plan_path(&site_state_root),
                    &supervisor_plan,
                )?;
                write_json(
                    &desired_links_path(&site_state_root),
                    &DesiredLinkState {
                        schema: DESIRED_LINKS_SCHEMA.to_string(),
                        version: DESIRED_LINKS_VERSION,
                        external_slots: external_env
                            .iter()
                            .filter_map(|(env_var, url)| {
                                env_var
                                    .strip_prefix("AMBER_EXTERNAL_SLOT_")
                                    .map(|_| (env_var.clone(), url.clone()))
                            })
                            .collect(),
                        export_peers: Vec::new(),
                    },
                )?;

                let mut supervisor = spawn_site_supervisor(&site_state_root)?;
                let launched = wait_for_site_ready(
                    site_id,
                    site_plan,
                    &site_state_root,
                    &mut supervisor,
                    &run_plan.mesh_scope,
                )
                .await?;

                let mut launched = launched;
                launched.receipt.supervisor_pid = supervisor.child.id();
                supervisor_children.insert(site_id.clone(), supervisor);

                register_new_site_links(
                    site_id,
                    &run_plan.links,
                    &mut launched,
                    &launched_by_site,
                    &state_root,
                )
                .await?;

                persist_site_state(
                    &state_root,
                    site_id,
                    &launched,
                    SiteLifecycleStatus::Running,
                    None,
                )?;
                started_site_receipts.insert(site_id.clone(), launched.receipt.clone());
                launched_by_site.insert(site_id.clone(), launched);
            }
            if wave_idx + 1 < run_plan.startup_waves.len()
                && let Some(delay) = test_wave_delay
            {
                sleep(delay).await;
            }
        }

        write_commit_marker(&run_root)?;
        emit_manager_event(
            "amber.run.committed",
            format!("committed mixed-site run {run_id}"),
            &[("amber.run_id", run_id.to_string())],
        );

        let receipt = RunReceipt {
            schema: RECEIPT_SCHEMA.to_string(),
            version: RECEIPT_VERSION,
            run_id: run_id.to_string(),
            mesh_scope: run_plan.mesh_scope.clone(),
            plan_path: run_plan_path.display().to_string(),
            source_plan_path: source_plan_path.map(|path| path.display().to_string()),
            run_root: run_root.display().to_string(),
            observability: observability_receipt.clone(),
            sites: launched_by_site
                .into_iter()
                .map(|(site_id, launched)| (site_id, launched.receipt))
                .collect(),
        };
        write_json(&receipt_path(&run_root), &receipt)?;
        Ok(receipt)
    }
    .await;

    if result.is_err() {
        let _ = write_stop_marker(&run_root);
        for supervisor in supervisor_children.values_mut() {
            send_sigterm(supervisor.child.id());
        }
        for supervisor in supervisor_children.values_mut() {
            let _ = wait_for_child_exit(&mut supervisor.child, PROCESS_SHUTDOWN_GRACE_PERIOD).await;
        }
        for (site_id, receipt) in &started_site_receipts {
            let state_path = site_state_path(&state_root, site_id);
            let already_terminal = read_json::<SiteManagerState>(&state_path, "site manager state")
                .ok()
                .is_some_and(|state| {
                    matches!(
                        state.status,
                        SiteLifecycleStatus::Stopped | SiteLifecycleStatus::Failed
                    )
                });
            if already_terminal {
                continue;
            }
            let _ = stop_site_from_receipt(receipt);
            let _ = write_site_state(
                &state_path,
                SiteManagerState {
                    schema: SITE_STATE_SCHEMA.to_string(),
                    version: SITE_STATE_VERSION,
                    run_id: run_id.to_string(),
                    site_id: site_id.clone(),
                    kind: receipt.kind,
                    status: SiteLifecycleStatus::Stopped,
                    artifact_dir: receipt.artifact_dir.clone(),
                    supervisor_pid: receipt.supervisor_pid,
                    process_pid: None,
                    compose_project: receipt.compose_project.clone(),
                    kubernetes_namespace: receipt.kubernetes_namespace.clone(),
                    port_forward_pid: None,
                    context: receipt.context.clone(),
                    router_control: receipt.router_control.clone(),
                    router_mesh_addr: receipt.router_mesh_addr.clone(),
                    router_identity_id: receipt.router_identity_id.clone(),
                    router_public_key_b64: receipt.router_public_key_b64.clone(),
                    last_error: Some("coordinator cleanup after failed startup".to_string()),
                },
            );
        }
        if let Some(pid) = observability_receipt
            .as_ref()
            .and_then(|value| value.sink_pid)
        {
            send_sigterm(pid);
        }
    }

    result
}

pub(crate) async fn stop_run(run_id: &str, storage_root_override: Option<&Path>) -> Result<()> {
    let storage_root = mixed_run_storage_root(storage_root_override)?;
    let run_root = storage_root.join("runs").join(run_id);
    let receipt: RunReceipt = read_json(&receipt_path(&run_root), "run receipt")?;
    for site in receipt.sites.values() {
        send_sigterm(site.supervisor_pid);
    }

    let deadline = Instant::now() + PROCESS_SHUTDOWN_GRACE_PERIOD;
    for (site_id, site) in &receipt.sites {
        let state_path = site_state_path(&run_root.join("state"), site_id);
        while Instant::now() < deadline {
            if let Ok(state) = read_json::<SiteManagerState>(&state_path, "site state")
                && matches!(
                    state.status,
                    SiteLifecycleStatus::Stopped | SiteLifecycleStatus::Failed
                )
            {
                break;
            }
            if !pid_is_alive(site.supervisor_pid) {
                stop_site_from_receipt(site)?;
                let stopped = SiteManagerState {
                    schema: SITE_STATE_SCHEMA.to_string(),
                    version: SITE_STATE_VERSION,
                    run_id: receipt.run_id.clone(),
                    site_id: site_id.clone(),
                    kind: site.kind,
                    status: SiteLifecycleStatus::Stopped,
                    artifact_dir: site.artifact_dir.clone(),
                    supervisor_pid: site.supervisor_pid,
                    process_pid: None,
                    compose_project: site.compose_project.clone(),
                    kubernetes_namespace: site.kubernetes_namespace.clone(),
                    port_forward_pid: None,
                    context: site.context.clone(),
                    router_control: site.router_control.clone(),
                    router_mesh_addr: site.router_mesh_addr.clone(),
                    router_identity_id: site.router_identity_id.clone(),
                    router_public_key_b64: site.router_public_key_b64.clone(),
                    last_error: None,
                };
                write_site_state(&state_path, stopped)?;
                break;
            }
            sleep(Duration::from_millis(200)).await;
        }
    }

    if let Some(observability) = receipt.observability.as_ref()
        && let Some(pid) = observability.sink_pid
    {
        send_sigterm(pid);
    }

    let _ = fs::remove_file(receipt_path(&run_root));
    Ok(())
}

fn stop_site_from_receipt(site: &SiteReceipt) -> Result<()> {
    match site.kind {
        SiteKind::Direct | SiteKind::Vm => {
            if let Some(pid) = site.process_pid {
                send_sigterm(pid);
            }
            if let Some(pid) = site.port_forward_pid {
                send_sigterm(pid);
            }
        }
        SiteKind::Compose => {
            if let Some(project_name) = site.compose_project.as_deref() {
                let status = compose_command(Some(project_name), Path::new(&site.artifact_dir))
                    .arg("down")
                    .arg("-v")
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
    Ok(())
}

pub(crate) async fn run_site_supervisor(plan_path: PathBuf) -> Result<()> {
    let plan: SiteSupervisorPlan = read_json(&plan_path, "site supervisor plan")?;
    let run_root = PathBuf::from(&plan.run_root);
    let stop_requested = install_signal_flag();
    let state_path = state_path_for_plan(&plan);

    init_manager_telemetry(
        &format!("/site/{}/manager", plan.site_id),
        &plan.mesh_scope,
        plan.observability_endpoint.as_deref(),
    );
    emit_manager_event(
        "amber.site_manager.starting",
        format!("starting site supervisor {}", plan.site_id),
        &[
            ("amber.run_id", plan.run_id.clone()),
            ("amber.site.id", plan.site_id.clone()),
            (
                "amber.site.kind",
                format!("{:?}", plan.kind).to_ascii_lowercase(),
            ),
        ],
    );

    let mut runtime = SupervisorRuntime {
        site_process: None,
        site_started: false,
        port_forward: None,
        last_start_attempt: None,
        last_stitch_refresh: None,
    };
    let mut last_written_state = None;
    let result: Result<()> = async {
        write_site_state_if_changed(
            &state_path,
            &mut last_written_state,
            build_site_state(&plan, &runtime, SiteLifecycleStatus::Starting, None, None),
        )?;

        loop {
            if stop_requested.load(Ordering::SeqCst) || stop_marker_path(&run_root).exists() {
                cleanup_site(&plan, &mut runtime).await?;
                emit_manager_event(
                    "amber.site_manager.stopped",
                    format!("stopped site supervisor {}", plan.site_id),
                    &[("amber.run_id", plan.run_id.clone())],
                );
                write_site_state_if_changed(
                    &state_path,
                    &mut last_written_state,
                    SiteManagerState {
                        schema: SITE_STATE_SCHEMA.to_string(),
                        version: SITE_STATE_VERSION,
                        run_id: plan.run_id.clone(),
                        site_id: plan.site_id.clone(),
                        kind: plan.kind,
                        status: SiteLifecycleStatus::Stopped,
                        artifact_dir: plan.artifact_dir.clone(),
                        supervisor_pid: std::process::id(),
                        process_pid: None,
                        compose_project: plan.compose_project.clone(),
                        kubernetes_namespace: plan.kubernetes_namespace.clone(),
                        port_forward_pid: None,
                        context: plan.context.clone(),
                        router_control: None,
                        router_mesh_addr: None,
                        router_identity_id: None,
                        router_public_key_b64: None,
                        last_error: None,
                    },
                )?;
                return Ok(());
            }

            if !commit_marker_path(&run_root).exists()
                && coordinator_has_exited(&run_root, plan.coordinator_pid)?
            {
                cleanup_site(&plan, &mut runtime).await?;
                write_site_state_if_changed(
                    &state_path,
                    &mut last_written_state,
                    SiteManagerState {
                        schema: SITE_STATE_SCHEMA.to_string(),
                        version: SITE_STATE_VERSION,
                        run_id: plan.run_id.clone(),
                        site_id: plan.site_id.clone(),
                        kind: plan.kind,
                        status: SiteLifecycleStatus::Stopped,
                        artifact_dir: plan.artifact_dir.clone(),
                        supervisor_pid: std::process::id(),
                        process_pid: None,
                        compose_project: plan.compose_project.clone(),
                        kubernetes_namespace: plan.kubernetes_namespace.clone(),
                        port_forward_pid: None,
                        context: plan.context.clone(),
                        router_control: None,
                        router_mesh_addr: None,
                        router_identity_id: None,
                        router_public_key_b64: None,
                        last_error: Some("coordinator exited before commit".to_string()),
                    },
                )?;
                return Ok(());
            }

            if should_attempt_launch(runtime.last_start_attempt) {
                ensure_site_running(&plan, &mut runtime).await?;
            }

            let discovery = match try_discover_site(&plan, &mut runtime).await {
                Ok(discovery) => discovery,
                Err(err) => {
                    write_site_state_if_changed(
                        &state_path,
                        &mut last_written_state,
                        build_site_state(
                            &plan,
                            &runtime,
                            SiteLifecycleStatus::Starting,
                            None,
                            Some(err.to_string()),
                        ),
                    )?;
                    sleep(SUPERVISOR_POLL_INTERVAL).await;
                    continue;
                }
            };

            if let Some(discovery) = discovery {
                if should_refresh_stitching(runtime.last_stitch_refresh) {
                    if let Err(err) = apply_desired_links(&plan, &discovery.control_endpoint).await
                    {
                        write_site_state_if_changed(
                            &state_path,
                            &mut last_written_state,
                            build_site_state(
                                &plan,
                                &runtime,
                                SiteLifecycleStatus::Starting,
                                Some(&discovery),
                                Some(err.to_string()),
                            ),
                        )?;
                        sleep(SUPERVISOR_POLL_INTERVAL).await;
                        continue;
                    }
                    runtime.last_stitch_refresh = Some(Instant::now());
                }

                let public_key_b64 = base64::engine::general_purpose::STANDARD
                    .encode(discovery.router_identity.public_key);
                write_site_state_if_changed(
                    &state_path,
                    &mut last_written_state,
                    SiteManagerState {
                        schema: SITE_STATE_SCHEMA.to_string(),
                        version: SITE_STATE_VERSION,
                        run_id: plan.run_id.clone(),
                        site_id: plan.site_id.clone(),
                        kind: plan.kind,
                        status: SiteLifecycleStatus::Running,
                        artifact_dir: plan.artifact_dir.clone(),
                        supervisor_pid: std::process::id(),
                        process_pid: runtime.site_process.as_ref().map(Child::id),
                        compose_project: plan.compose_project.clone(),
                        kubernetes_namespace: plan.kubernetes_namespace.clone(),
                        port_forward_pid: runtime.port_forward.as_ref().map(Child::id),
                        context: plan.context.clone(),
                        router_control: Some(discovery.control_endpoint.to_string()),
                        router_mesh_addr: discovery.router_addr.map(|addr| addr.to_string()),
                        router_identity_id: Some(discovery.router_identity.id),
                        router_public_key_b64: Some(public_key_b64),
                        last_error: None,
                    },
                )?;
            } else {
                write_site_state_if_changed(
                    &state_path,
                    &mut last_written_state,
                    build_site_state(&plan, &runtime, SiteLifecycleStatus::Starting, None, None),
                )?;
            }

            sleep(SUPERVISOR_POLL_INTERVAL).await;
        }
    }
    .await;

    if let Err(err) = &result {
        let _ = cleanup_site(&plan, &mut runtime).await;
        let _ = write_site_state_if_changed(
            &state_path,
            &mut last_written_state,
            build_site_state(
                &plan,
                &runtime,
                SiteLifecycleStatus::Failed,
                None,
                Some(err.to_string()),
            ),
        );
    }

    result
}

pub(crate) async fn run_observability_sink(plan_path: PathBuf) -> Result<()> {
    let plan: ObservabilitySinkPlan = read_json(&plan_path, "observability sink plan")?;
    let listen_addr: SocketAddr = plan.listen_addr.parse().map_err(|err| {
        miette::miette!(
            "invalid observability listen addr {}: {err}",
            plan.listen_addr
        )
    })?;
    let run_root = PathBuf::from(&plan.run_root);
    let stop_requested = install_signal_flag();
    let listener = TcpListener::bind(listen_addr)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to bind observability sink at {listen_addr}"))?;
    listener
        .set_nonblocking(true)
        .into_diagnostic()
        .wrap_err("failed to configure observability listener")?;

    let state_path = observability_state_path(&run_root);
    write_json(
        &state_path,
        &ObservabilityReceipt {
            endpoint: plan.advertise_endpoint.clone(),
            sink_pid: Some(std::process::id()),
            requests_log: Some(plan.requests_log.clone()),
        },
    )?;

    loop {
        if stop_requested.load(Ordering::SeqCst) || stop_marker_path(&run_root).exists() {
            return Ok(());
        }

        match listener.accept() {
            Ok((mut stream, _)) => {
                handle_otlp_connection(&mut stream, Path::new(&plan.requests_log))?
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(err) => {
                return Err(miette::miette!("observability sink accept failed: {err}"));
            }
        }
    }
}

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

async fn start_observability_if_needed(
    run_root: &Path,
    run_id: &str,
    mesh_scope: &str,
    observability: Option<&str>,
) -> Result<Option<ObservabilityReceipt>> {
    let Some(observability) = observability
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };

    if observability == "local" {
        let listen_port = reserve_loopback_port()?;
        let listen_addr = SocketAddr::from(([0, 0, 0, 0], listen_port));
        let advertise_endpoint = format!("http://127.0.0.1:{listen_port}");
        let requests_log = run_root.join("observability").join("requests.log");
        let plan = ObservabilitySinkPlan {
            schema: OTLP_SINK_PLAN_SCHEMA.to_string(),
            version: OTLP_SINK_PLAN_VERSION,
            run_id: run_id.to_string(),
            mesh_scope: mesh_scope.to_string(),
            run_root: run_root.display().to_string(),
            listen_addr: listen_addr.to_string(),
            advertise_endpoint: advertise_endpoint.clone(),
            requests_log: requests_log.display().to_string(),
        };
        let plan_path = observability_plan_path(run_root);
        write_json(&plan_path, &plan)?;
        let mut child = spawn_detached_child(
            &PathBuf::from(&plan.run_root),
            &run_root.join("observability").join("sink.log"),
            |cmd| {
                cmd.arg("run-observability-sink")
                    .arg("--plan")
                    .arg(&plan_path);
            },
        )?;
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Some(status) = child.try_wait().into_diagnostic()? {
                return Err(miette::miette!(
                    "observability sink exited before becoming ready with status {status}"
                ));
            }
            if observability_state_path(run_root).is_file() {
                return Ok(Some(ObservabilityReceipt {
                    endpoint: advertise_endpoint,
                    sink_pid: Some(child.id()),
                    requests_log: Some(requests_log.display().to_string()),
                }));
            }
            sleep(Duration::from_millis(100)).await;
        }
        return Err(miette::miette!("timed out waiting for observability sink"));
    }

    Ok(Some(ObservabilityReceipt {
        endpoint: observability.to_string(),
        sink_pid: None,
        requests_log: None,
    }))
}

fn materialize_site_artifacts(
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

fn patch_site_artifacts(
    artifact_dir: &Path,
    kind: SiteKind,
    external_env: &BTreeMap<String, String>,
    observability_endpoint: Option<&str>,
) -> Result<()> {
    if matches!(kind, SiteKind::Kubernetes) {
        let env_file = artifact_dir.join(DEFAULT_EXTERNAL_ENV_FILE);
        if env_file.is_file() {
            let mut lines = String::new();
            for (key, value) in external_env {
                lines.push_str(key);
                lines.push('=');
                lines.push_str(value);
                lines.push('\n');
            }
            fs::write(&env_file, lines)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to write {}", env_file.display()))?;
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

fn external_slot_env_for_site(
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
        let provider = launched_by_site.get(&link.provider_site).ok_or_else(|| {
            miette::miette!(
                "provider site `{}` has not been launched before consumer site `{site_id}`",
                link.provider_site
            )
        })?;
        env.insert(
            amber_compiler::mesh::external_slot_env_var(&link.external_slot_name),
            external_slot_url(provider, link, consumer_kind)?,
        );
    }
    Ok(env)
}

fn launch_env(
    run_id: &str,
    mesh_scope: &str,
    kind: SiteKind,
    external_env: &BTreeMap<String, String>,
    observability_endpoint: Option<&str>,
) -> Result<BTreeMap<String, String>> {
    let mut env = external_env.clone();
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

fn build_supervisor_plan(
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
        router_mesh_port: if matches!(input.site_plan.site.kind, SiteKind::Direct | SiteKind::Vm) {
            Some(reserve_loopback_port()?)
        } else {
            None
        },
        compose_project: (input.site_plan.site.kind == SiteKind::Compose)
            .then(|| compose_project_name(input.run_id, input.site_id)),
        kubernetes_namespace: (input.site_plan.site.kind == SiteKind::Kubernetes)
            .then(|| kubernetes_namespace_from_artifact(input.artifact_dir))
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
        launch_env,
    })
}

fn spawn_site_supervisor(site_state_root: &Path) -> Result<SupervisorChild> {
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

async fn wait_for_site_ready(
    site_id: &str,
    site_plan: &RunSitePlan,
    site_state_root: &Path,
    supervisor: &mut SupervisorChild,
    mesh_scope: &str,
) -> Result<LaunchedSite> {
    let deadline = Instant::now() + SITE_READY_TIMEOUT;
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

async fn register_new_site_links(
    site_id: &str,
    links: &[RunLink],
    launched: &mut LaunchedSite,
    launched_by_site: &BTreeMap<String, LaunchedSite>,
    state_root: &Path,
) -> Result<()> {
    for link in links {
        if link.consumer_site != site_id {
            continue;
        }
        let provider = launched_by_site.get(&link.provider_site).ok_or_else(|| {
            miette::miette!("provider site `{}` is not active", link.provider_site)
        })?;
        let external_url = external_slot_url(provider, link, launched.receipt.kind)?;
        let consumer_key =
            base64::engine::general_purpose::STANDARD.encode(launched.router_identity.public_key);

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
            },
        )?;
    }
    Ok(())
}

fn update_desired_links_for_consumer(
    site_state_root: &Path,
    slot_name: &str,
    url: &str,
) -> Result<()> {
    let path = desired_links_path(site_state_root);
    let mut state: DesiredLinkState = if path.is_file() {
        read_json(&path, "desired links")?
    } else {
        DesiredLinkState {
            schema: DESIRED_LINKS_SCHEMA.to_string(),
            version: DESIRED_LINKS_VERSION,
            external_slots: BTreeMap::new(),
            export_peers: Vec::new(),
        }
    };
    state.external_slots.insert(
        amber_compiler::mesh::external_slot_env_var(slot_name),
        url.to_string(),
    );
    write_json(&path, &state)
}

fn update_desired_links_for_provider(
    site_state_root: &Path,
    peer: DesiredExportPeer,
) -> Result<()> {
    let path = desired_links_path(site_state_root);
    let mut state: DesiredLinkState = if path.is_file() {
        read_json(&path, "desired links")?
    } else {
        DesiredLinkState {
            schema: DESIRED_LINKS_SCHEMA.to_string(),
            version: DESIRED_LINKS_VERSION,
            external_slots: BTreeMap::new(),
            export_peers: Vec::new(),
        }
    };
    if !state.export_peers.contains(&peer) {
        state.export_peers.push(peer);
    }
    write_json(&path, &state)
}

fn launched_site_from_state(
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
        },
        router_control,
        router_identity,
        router_addr,
    })
}

async fn ensure_site_running(
    plan: &SiteSupervisorPlan,
    runtime: &mut SupervisorRuntime,
) -> Result<()> {
    reap_child(&mut runtime.site_process)?;
    reap_child(&mut runtime.port_forward)?;

    match plan.kind {
        SiteKind::Direct => {
            if runtime.site_process.is_none() {
                runtime.last_start_attempt = Some(Instant::now());
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
                let status = compose_command(
                    plan.compose_project.as_deref(),
                    Path::new(&plan.artifact_dir),
                )
                .envs(plan.launch_env.clone())
                .arg("up")
                .arg("-d")
                .status()
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to start compose site `{}`", plan.site_id))?;
                if !status.success() {
                    return Err(miette::miette!(
                        "compose site `{}` failed to start with status {status}",
                        plan.site_id
                    ));
                }
                runtime.site_started = true;
            }
        }
        SiteKind::Kubernetes => {
            if !runtime.site_started {
                runtime.last_start_attempt = Some(Instant::now());
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
                runtime.site_started = true;
            }
            if runtime.port_forward.is_none() {
                runtime.port_forward = Some(spawn_port_forward(plan)?);
            }
        }
    }
    Ok(())
}

async fn try_discover_site(
    plan: &SiteSupervisorPlan,
    runtime: &mut SupervisorRuntime,
) -> Result<Option<RouterDiscovery>> {
    reap_child(&mut runtime.site_process)?;
    reap_child(&mut runtime.port_forward)?;
    let discovery = match plan.kind {
        SiteKind::Direct => try_discover_direct_site(plan, runtime).await,
        SiteKind::Vm => try_discover_vm_site(plan, runtime).await,
        SiteKind::Compose => try_discover_compose_site(plan).await,
        SiteKind::Kubernetes => try_discover_kubernetes_site(plan, runtime).await,
    }?;
    if discovery.is_none() && plan.kind == SiteKind::Compose {
        runtime.site_started = false;
    }
    Ok(discovery)
}

async fn try_discover_direct_site(
    plan: &SiteSupervisorPlan,
    runtime: &SupervisorRuntime,
) -> Result<Option<RouterDiscovery>> {
    let Some(site_process) = runtime.site_process.as_ref() else {
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
        if let Ok(router_identity) = fetch_router_identity(&control_endpoint).await {
            let router_addr = SocketAddr::from(([127, 0, 0, 1], router_mesh_port));
            if !router_mesh_listener_ready(router_addr).await {
                return Ok(None);
            }
            let _ = site_process;
            return Ok(Some(RouterDiscovery {
                control_endpoint,
                router_identity,
                router_addr: Some(router_addr),
            }));
        }
    }
    Ok(None)
}

async fn try_discover_vm_site(
    plan: &SiteSupervisorPlan,
    runtime: &SupervisorRuntime,
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
    if let Ok(router_identity) = fetch_router_identity(&control_endpoint).await {
        let router_addr = SocketAddr::from(([127, 0, 0, 1], router_mesh_port));
        if !router_mesh_listener_ready(router_addr).await {
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

async fn try_discover_compose_site(plan: &SiteSupervisorPlan) -> Result<Option<RouterDiscovery>> {
    discover_router_for_output(&plan.artifact_dir, plan.compose_project.as_deref(), true)
        .await
        .map(Some)
        .wrap_err_with(|| format!("compose router discovery for site `{}`", plan.site_id))
}

async fn try_discover_kubernetes_site(
    plan: &SiteSupervisorPlan,
    runtime: &mut SupervisorRuntime,
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
    match fetch_router_identity(&control_endpoint).await {
        Ok(router_identity) => Ok(Some(RouterDiscovery {
            control_endpoint,
            router_identity,
            router_addr: Some(SocketAddr::from(([127, 0, 0, 1], mesh_port))),
        })),
        Err(_) => Ok(None),
    }
}

async fn apply_desired_links(plan: &SiteSupervisorPlan, endpoint: &ControlEndpoint) -> Result<()> {
    let desired: DesiredLinkState = read_json(
        &desired_links_path(Path::new(&plan.site_state_root)),
        "desired links",
    )?;
    for (env_var, url) in &desired.external_slots {
        let slot = env_var
            .strip_prefix("AMBER_EXTERNAL_SLOT_")
            .unwrap_or(env_var.as_str())
            .to_ascii_lowercase();
        register_external_slot_with_retry(endpoint, &slot, url, Duration::from_secs(2)).await?;
    }
    for peer in &desired.export_peers {
        register_export_peer_with_retry(
            endpoint,
            &peer.export_name,
            &peer.peer_id,
            &peer.peer_key_b64,
            &peer.protocol,
            Duration::from_secs(2),
        )
        .await?;
    }
    Ok(())
}

async fn cleanup_site(plan: &SiteSupervisorPlan, runtime: &mut SupervisorRuntime) -> Result<()> {
    reap_child(&mut runtime.site_process)?;
    reap_child(&mut runtime.port_forward)?;

    if let Some(child) = runtime.site_process.as_mut() {
        stop_child(child).await?;
    }
    if let Some(child) = runtime.port_forward.as_mut() {
        stop_child(child).await?;
    }
    runtime.site_process = None;
    runtime.site_started = false;
    runtime.port_forward = None;

    match plan.kind {
        SiteKind::Compose => {
            if let Some(project_name) = plan.compose_project.as_deref() {
                let status = compose_command(Some(project_name), Path::new(&plan.artifact_dir))
                    .arg("down")
                    .arg("-v")
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
    Ok(())
}

fn build_site_state(
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
        last_error,
    }
}

fn persist_site_state(
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
            last_error,
        },
    )
}

fn write_site_state(path: &Path, state: SiteManagerState) -> Result<()> {
    write_json(path, &state)
}

fn write_site_state_if_changed(
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

fn compose_command(project_name: Option<&str>, artifact_dir: &Path) -> Command {
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

fn kubectl_command(context: Option<&str>) -> Command {
    let mut cmd = Command::new("kubectl");
    if let Some(context) = context {
        cmd.arg("--context").arg(context);
    }
    cmd
}

fn ensure_kubernetes_namespace(plan: &SiteSupervisorPlan) -> Result<()> {
    let namespace = required_str(plan.kubernetes_namespace.as_deref(), "kubernetes namespace")?;
    let deadline = Instant::now() + KUBERNETES_NAMESPACE_READY_TIMEOUT;
    loop {
        let output = kubectl_command(plan.context.as_deref())
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
        } else if Instant::now() >= deadline {
            break;
        } else {
            let status = kubectl_command(plan.context.as_deref())
                .arg("create")
                .arg("namespace")
                .arg(namespace)
                .status()
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to create kubernetes namespace `{namespace}`"))?;
            if status.success() {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err(miette::miette!(
                "kubernetes namespace `{namespace}` is still terminating after {}s",
                KUBERNETES_NAMESPACE_READY_TIMEOUT.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    unreachable!("deadline check should have returned")
}

fn compose_project_name(run_id: &str, site_id: &str) -> String {
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

    let exe = env::current_exe()
        .into_diagnostic()
        .wrap_err("failed to resolve amber executable path")?;
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

fn spawn_runtime_process(
    site_state_root: &Path,
    log_name: &str,
    extra_env: &BTreeMap<String, String>,
    build: impl FnOnce(&mut Command),
) -> Result<Child> {
    let exe = env::current_exe()
        .into_diagnostic()
        .wrap_err("failed to resolve amber executable path")?;
    let log_path = site_state_root.join(log_name);
    let log = fs::File::create(&log_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create {}", log_path.display()))?;
    let log_err = log
        .try_clone()
        .into_diagnostic()
        .wrap_err("failed to clone site log")?;
    let mut cmd = Command::new(exe);
    cmd.envs(extra_env);
    cmd.stdout(Stdio::from(log));
    cmd.stderr(Stdio::from(log_err));
    build(&mut cmd);
    cmd.spawn()
        .into_diagnostic()
        .wrap_err("failed to spawn runtime child")
}

fn spawn_port_forward(plan: &SiteSupervisorPlan) -> Result<Child> {
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
        .arg(format!("{control_port}:24100"))
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err));
    cmd.spawn()
        .into_diagnostic()
        .wrap_err("failed to spawn kubectl port-forward")
}

fn required_path<'a>(value: Option<&'a str>, label: &str) -> &'a str {
    value.unwrap_or_else(|| panic!("missing {label}"))
}

fn required_str<'a>(value: Option<&'a str>, label: &str) -> Result<&'a str> {
    value.ok_or_else(|| miette::miette!("missing {label}"))
}

fn should_attempt_launch(last_start_attempt: Option<Instant>) -> bool {
    last_start_attempt.is_none_or(|instant| instant.elapsed() >= RESTART_BACKOFF)
}

fn should_refresh_stitching(last_refresh: Option<Instant>) -> bool {
    last_refresh.is_none_or(|instant| instant.elapsed() >= STITCH_REFRESH_INTERVAL)
}

fn reap_child(child: &mut Option<Child>) -> Result<()> {
    let Some(process) = child.as_mut() else {
        return Ok(());
    };
    if process.try_wait().into_diagnostic()?.is_some() {
        *child = None;
    }
    Ok(())
}

async fn stop_child(child: &mut Child) -> Result<()> {
    send_sigterm(child.id());
    let _ = wait_for_child_exit(child, PROCESS_SHUTDOWN_GRACE_PERIOD).await;
    Ok(())
}

async fn wait_for_child_exit(child: &mut Child, timeout: Duration) -> Result<()> {
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

fn external_slot_url(
    provider: &LaunchedSite,
    link: &RunLink,
    consumer_kind: SiteKind,
) -> Result<String> {
    let host = match consumer_kind {
        SiteKind::Direct | SiteKind::Vm => "127.0.0.1",
        SiteKind::Compose | SiteKind::Kubernetes => "host.docker.internal",
    };
    let mut mesh_url = Url::parse(&format!("mesh://{}:{}", host, provider.router_addr.port()))
        .into_diagnostic()
        .wrap_err("failed to build mesh link url")?;
    let peer_key =
        base64::engine::general_purpose::STANDARD.encode(provider.router_identity.public_key);
    mesh_url
        .query_pairs_mut()
        .append_pair("peer_id", &provider.router_identity.id)
        .append_pair("peer_key", &peer_key)
        .append_pair(
            "route_id",
            &router_export_route_id(&link.export_name, mesh_protocol(link.protocol)?),
        )
        .append_pair("capability", &link.export_name);
    Ok(mesh_url.to_string())
}

fn mesh_protocol(protocol: NetworkProtocol) -> Result<MeshProtocol> {
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

fn kubernetes_namespace_from_artifact(artifact_dir: &Path) -> Result<String> {
    let kustomization = artifact_dir.join("kustomization.yaml");
    if kustomization.is_file() {
        let contents = fs::read_to_string(&kustomization)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read {}", kustomization.display()))?;
        for line in contents.lines() {
            let trimmed = line.trim();
            if let Some(namespace) = trimmed.strip_prefix("namespace:") {
                let namespace = namespace.trim();
                if !namespace.is_empty() {
                    return Ok(namespace.to_string());
                }
            }
        }
    }

    for entry in walk_files(artifact_dir)? {
        if entry.extension().and_then(|ext| ext.to_str()) != Some("yaml") {
            continue;
        }
        let contents = fs::read_to_string(&entry)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read kubernetes file {}", entry.display()))?;
        if !contents.contains("\nkind: Namespace\n") && !contents.starts_with("kind: Namespace\n") {
            continue;
        }
        let mut saw_metadata = false;
        for line in contents.lines() {
            let trimmed = line.trim();
            if trimmed == "metadata:" {
                saw_metadata = true;
                continue;
            }
            if saw_metadata && let Some(name) = trimmed.strip_prefix("name:") {
                return Ok(name.trim().to_string());
            }
        }
    }
    Err(miette::miette!(
        "kubernetes artifact {} does not contain a Namespace resource",
        artifact_dir.display()
    ))
}

fn walk_files(root: &Path) -> Result<Vec<PathBuf>> {
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

fn observability_endpoint_for_site(kind: SiteKind, endpoint: &str) -> Result<String> {
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
        url.set_host(Some(CONTAINER_HOST_ALIAS))
            .map_err(|_| miette::miette!("failed to rewrite observability endpoint {endpoint}"))?;
    }
    Ok(url.to_string())
}

fn reserve_loopback_port() -> Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .into_diagnostic()
        .wrap_err("failed to allocate a loopback port")?;
    Ok(listener.local_addr().into_diagnostic()?.port())
}

pub(crate) fn new_run_id() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("run-{millis:x}-{:x}", std::process::id())
}

fn receipt_path(run_root: &Path) -> PathBuf {
    run_root.join("receipt.json")
}

fn run_plan_path(run_root: &Path) -> PathBuf {
    run_root.join("run-plan.json")
}

fn site_state_path(state_root: &Path, site_id: &str) -> PathBuf {
    state_root.join(site_id).join("manager-state.json")
}

fn state_path_for_plan(plan: &SiteSupervisorPlan) -> PathBuf {
    Path::new(&plan.site_state_root).join("manager-state.json")
}

fn site_supervisor_plan_path(site_state_root: &Path) -> PathBuf {
    site_state_root.join("site-supervisor-plan.json")
}

fn desired_links_path(site_state_root: &Path) -> PathBuf {
    site_state_root.join("desired-links.json")
}

fn commit_marker_path(run_root: &Path) -> PathBuf {
    run_root.join("committed")
}

fn coordinator_lock_path(run_root: &Path) -> PathBuf {
    run_root.join("coordinator.lock")
}

fn stop_marker_path(run_root: &Path) -> PathBuf {
    run_root.join("stop-requested")
}

async fn router_mesh_listener_ready(addr: SocketAddr) -> bool {
    matches!(
        tokio::time::timeout(
            Duration::from_millis(250),
            tokio::net::TcpStream::connect(addr)
        )
        .await,
        Ok(Ok(_))
    )
}

fn observability_plan_path(run_root: &Path) -> PathBuf {
    run_root.join("observability").join("sink-plan.json")
}

fn observability_state_path(run_root: &Path) -> PathBuf {
    run_root.join("observability").join("sink-state.json")
}

fn write_commit_marker(run_root: &Path) -> Result<()> {
    fs::write(commit_marker_path(run_root), b"committed")
        .into_diagnostic()
        .wrap_err("failed to write commit marker")
}

fn write_stop_marker(run_root: &Path) -> Result<()> {
    fs::write(stop_marker_path(run_root), b"stop")
        .into_diagnostic()
        .wrap_err("failed to write stop marker")
}

fn test_wave_delay() -> Result<Option<Duration>> {
    let Some(raw) = env::var_os(TEST_WAVE_DELAY_ENV) else {
        return Ok(None);
    };
    let raw = raw.to_string_lossy();
    let millis = raw
        .parse::<u64>()
        .map_err(|err| miette::miette!("invalid {TEST_WAVE_DELAY_ENV} value `{raw}`: {err}"))?;
    Ok(Some(Duration::from_millis(millis)))
}

fn hold_coordinator_lock(run_root: &Path) -> Result<fs::File> {
    let path = coordinator_lock_path(run_root);
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to open coordinator lock {}", path.display()))?;
    set_close_on_exec(&file)?;

    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;

        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            return Err(miette::miette!(
                "failed to acquire coordinator lock {}: {err}",
                path.display()
            ));
        }
    }

    Ok(file)
}

fn set_close_on_exec(file: &fs::File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;

        let fd = file.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags == -1 {
            return Err(miette::miette!(
                "failed to read coordinator lock flags: {}",
                std::io::Error::last_os_error()
            ));
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
            return Err(miette::miette!(
                "failed to set coordinator lock close-on-exec: {}",
                std::io::Error::last_os_error()
            ));
        }
    }

    #[cfg(not(unix))]
    {
        let _ = file;
    }

    Ok(())
}

fn coordinator_has_exited(run_root: &Path, coordinator_pid: u32) -> Result<bool> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;

        let path = coordinator_lock_path(run_root);
        let file = match fs::OpenOptions::new().read(true).write(true).open(&path) {
            Ok(file) => file,
            Err(_) => return Ok(!pid_is_alive(coordinator_pid)),
        };
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) };
        if rc == 0 {
            let _ = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
            return Ok(true);
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Ok(false);
        }
        Ok(!pid_is_alive(coordinator_pid))
    }

    #[cfg(not(unix))]
    {
        let _ = run_root;
        Ok(!pid_is_alive(coordinator_pid))
    }
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to create {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|err| miette::miette!("failed to serialize {}: {err}", path.display()))?;
    write_bytes_atomic(path, &bytes)
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("tmp");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp_path = path.with_file_name(format!(".{file_name}.tmp-{}-{nonce}", std::process::id()));

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create {}", tmp_path.display()))?;
    if let Err(err) = file.write_all(bytes) {
        let _ = fs::remove_file(&tmp_path);
        return Err(miette::miette!(
            "failed to write {}: {err}",
            tmp_path.display()
        ));
    }
    if let Err(err) = file.sync_all() {
        let _ = fs::remove_file(&tmp_path);
        return Err(miette::miette!(
            "failed to sync {}: {err}",
            tmp_path.display()
        ));
    }
    drop(file);

    if let Err(err) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(miette::miette!(
            "failed to replace {} with {}: {err}",
            path.display(),
            tmp_path.display()
        ));
    }

    Ok(())
}

fn canonicalize_existing_path(path: &Path, description: &str) -> Result<PathBuf> {
    path.canonicalize()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to resolve {description} {}", path.display()))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path, label: &str) -> Result<T> {
    let bytes = fs::read(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {} {}", label, path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|err| miette::miette!("invalid {} {}: {err}", label, path.display()))
}

fn parse_control_endpoint(raw: &str) -> Result<ControlEndpoint> {
    if let Some(path) = raw.strip_prefix("unix://") {
        return Ok(ControlEndpoint::Unix(PathBuf::from(path)));
    }
    if let Some(rest) = raw.strip_prefix("volume://")
        && let Some((volume, socket_path)) = rest.split_once('/')
    {
        return Ok(ControlEndpoint::VolumeSocket {
            volume: volume.to_string(),
            socket_path: format!("/{}", socket_path),
        });
    }
    Ok(ControlEndpoint::Tcp(raw.to_string()))
}

fn decode_public_key(value: &str) -> Result<[u8; 32]> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .into_diagnostic()
        .wrap_err("invalid base64 router public key")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| miette::miette!("invalid router public key length"))
}

fn pid_is_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        unsafe {
            libc::kill(pid as i32, 0) == 0
                || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
        }
    }

    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

fn send_sigterm(pid: u32) {
    #[cfg(unix)]
    {
        let _ = unsafe { libc::kill(pid as i32, libc::SIGTERM) };
    }

    #[cfg(not(unix))]
    {
        let _ = pid;
    }
}

fn install_signal_flag() -> Arc<AtomicBool> {
    let flag = Arc::new(AtomicBool::new(false));

    #[cfg(unix)]
    {
        let flag_clone = Arc::clone(&flag);
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};

            let mut sigterm = signal(SignalKind::terminate()).ok();
            let mut sighup = signal(SignalKind::hangup()).ok();
            let mut sigint = signal(SignalKind::interrupt()).ok();

            tokio::select! {
                _ = async {
                    if let Some(sigterm) = sigterm.as_mut() {
                        sigterm.recv().await;
                    }
                } => {}
                _ = async {
                    if let Some(sighup) = sighup.as_mut() {
                        sighup.recv().await;
                    }
                } => {}
                _ = async {
                    if let Some(sigint) = sigint.as_mut() {
                        sigint.recv().await;
                    }
                } => {}
            }

            flag_clone.store(true, Ordering::SeqCst);
        });
    }

    flag
}

fn init_manager_telemetry(moniker: &str, mesh_scope: &str, endpoint: Option<&str>) {
    let _ = (moniker, mesh_scope);
    let endpoint = endpoint
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let state = MANAGER_OBSERVABILITY_ENDPOINT.get_or_init(|| Mutex::new(None));
    *state
        .lock()
        .expect("manager observability endpoint lock should not be poisoned") = endpoint;
}

fn emit_manager_event(event_name: &'static str, body: String, attributes: &[(&str, String)]) {
    let Some(endpoint) = MANAGER_OBSERVABILITY_ENDPOINT.get().and_then(|state| {
        state
            .lock()
            .expect("manager observability endpoint lock should not be poisoned")
            .clone()
    }) else {
        return;
    };
    let payload = serde_json::to_vec(&serde_json::json!({
        "event": event_name,
        "body": body,
        "attributes": attributes.iter().map(|(key, value)| ((*key).to_string(), value.clone())).collect::<BTreeMap<_, _>>(),
    }))
    .unwrap_or_default();
    let _ = send_manager_observability(&endpoint, "/v1/logs", &payload);
}

fn handle_otlp_connection(stream: &mut TcpStream, requests_log: &Path) -> Result<()> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .into_diagnostic()
        .wrap_err("failed to configure observability stream timeout")?;

    let mut buf = Vec::new();
    let header_end = loop {
        let mut chunk = [0u8; 4096];
        let read = stream
            .read(&mut chunk)
            .into_diagnostic()
            .wrap_err("failed to read observability request headers")?;
        if read == 0 {
            return Err(miette::miette!(
                "observability client closed the connection before sending request headers"
            ));
        }
        buf.extend_from_slice(&chunk[..read]);
        if let Some(end) = find_header_end(&buf) {
            break end;
        }
    };

    let header = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let path = header
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_string();
    let content_length = header
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then_some(value.trim())
        })
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let body_start = header_end + 4;
    while buf.len().saturating_sub(body_start) < content_length {
        let mut chunk = [0u8; 4096];
        let read = stream
            .read(&mut chunk)
            .into_diagnostic()
            .wrap_err("failed to read observability request body")?;
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
    }
    let body_len = buf.len().saturating_sub(body_start);
    if let Some(parent) = requests_log.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to create {}", parent.display()))?;
    }
    let mut log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(requests_log)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to open {}", requests_log.display()))?;
    writeln!(log, "{}\t{}", path, body_len)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to append {}", requests_log.display()))?;
    stream
        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .into_diagnostic()
        .wrap_err("failed to write observability response")?;
    Ok(())
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

fn send_manager_observability(endpoint: &str, path: &str, body: &[u8]) -> Result<()> {
    let url = Url::parse(endpoint)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid manager observability endpoint {endpoint}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| miette::miette!("manager observability endpoint is missing a host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| miette::miette!("manager observability endpoint is missing a port"))?;
    let mut stream = TcpStream::connect((host, port))
        .into_diagnostic()
        .wrap_err_with(|| {
            format!("failed to connect to manager observability endpoint {endpoint}")
        })?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .into_diagnostic()
        .wrap_err("failed to configure manager observability write timeout")?;
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: \
         application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .into_diagnostic()
        .wrap_err("failed to write manager observability request headers")?;
    stream
        .write_all(body)
        .into_diagnostic()
        .wrap_err("failed to write manager observability request body")?;
    Ok(())
}
