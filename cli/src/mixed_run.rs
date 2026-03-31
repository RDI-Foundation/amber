use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    env, fs,
    future::Future,
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

use amber_compiler::{
    mesh::ProxyMetadata,
    reporter::vm::{VM_PLAN_FILENAME, VmPlan},
    run_plan::{RunLink, RunPlan, RunSitePlan, SiteKind},
};
use amber_manifest::{CapabilityKind, CapabilityTransport, NetworkProtocol};
use amber_mesh::{
    InboundRoute, InboundTarget, MeshConfig, MeshConfigPublic, MeshIdentity, MeshIdentityPublic,
    MeshPeer, MeshProtocol, OutboundRoute, TransportConfig, component_route_id,
    router_export_route_id,
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
    DirectLaunchProcessPreview, DirectSiteLaunchPreview, build_direct_site_launch_preview,
    direct_current_control_socket_path, direct_runtime_state_path,
    run_inputs::{collect_run_interface, validate_export_bindings, validate_slot_bindings},
    site_proxy_metadata::load_site_proxy_metadata,
    tcp_readiness::{wait_for_http_response, wait_for_stable_endpoint},
    vm_runtime::{
        TCG_VM_STARTUP_TIMEOUT, VmLaunchPreview, VmRuntimeState, VmSiteLaunchPreview,
        build_vm_site_launch_preview, vm_current_control_socket_path, vm_uses_tcg_accel,
    },
};
mod launch_bundle;
mod outside_proxy;
mod supervisor;

pub(crate) use self::{launch_bundle::*, outside_proxy::*, supervisor::*};

const RECEIPT_SCHEMA: &str = "amber.run.receipt";
const RECEIPT_VERSION: u32 = 3;
const LAUNCH_BUNDLE_SCHEMA: &str = "amber.run.launch_bundle";
const LAUNCH_BUNDLE_VERSION: u32 = 1;
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
const OUTSIDE_PROXY_PLAN_SCHEMA: &str = "amber.run.outside_proxy";
const OUTSIDE_PROXY_PLAN_VERSION: u32 = 1;
const OUTSIDE_PROXY_STATE_SCHEMA: &str = "amber.run.outside_proxy_state";
const OUTSIDE_PROXY_STATE_VERSION: u32 = 1;

const ROUTER_CONTROL_TIMEOUT: Duration = Duration::from_secs(30);
const SUPERVISOR_POLL_INTERVAL: Duration = Duration::from_millis(500);
const RESTART_BACKOFF: Duration = Duration::from_secs(1);
const STITCH_REFRESH_INTERVAL: Duration = Duration::from_secs(2);
const SITE_DISCOVERY_STABILITY_WINDOW: Duration = Duration::from_secs(1);
const PROCESS_SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(10);
const SITE_SUPERVISOR_STOP_TIMEOUT: Duration = Duration::from_secs(60);
const FORCED_SUPERVISOR_EXIT_GRACE_PERIOD: Duration = Duration::from_secs(5);
const KUBERNETES_NAMESPACE_READY_TIMEOUT: Duration = Duration::from_secs(60);
const KUBERNETES_WORKLOAD_READY_TIMEOUT: Duration = Duration::from_secs(120);
const KUBERNETES_SITE_READY_BUFFER: Duration = Duration::from_secs(30);
const VM_LOCAL_TARGET_READY_TIMEOUT: Duration = Duration::from_secs(1);

const DEFAULT_EXTERNAL_ENV_FILE: &str = "router-external.env";
const DEFAULT_K8S_OTEL_UPSTREAM: &str = "http://host.docker.internal:18890";
const CONTAINER_HOST_ALIAS: &str = "host.docker.internal";

static MANAGER_OBSERVABILITY_ENDPOINT: OnceLock<Mutex<Option<String>>> = OnceLock::new();
static KUBERNETES_CONTAINER_HOST_IP: OnceLock<Option<String>> = OnceLock::new();

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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) bridge_proxies: Vec<BridgeProxyReceipt>,
    pub(crate) sites: BTreeMap<String, SiteReceipt>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct BridgeProxyReceipt {
    pub(crate) export_name: String,
    pub(crate) pid: u32,
    pub(crate) listen: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LaunchBundleManifest {
    schema: String,
    version: u32,
    run_id: String,
    mesh_scope: String,
    plan_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_plan_path: Option<String>,
    bundle_root: String,
    assignments: BTreeMap<String, String>,
    startup_waves: Vec<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    stitching: Vec<LaunchBundleLinkPreview>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    observability: Option<LaunchBundleObservability>,
    sites: BTreeMap<String, LaunchBundleSite>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LaunchBundleObservability {
    endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    plan_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    state_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requests_log: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    launch_commands: Vec<LaunchCommandPreview>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LaunchBundleSite {
    kind: SiteKind,
    router_identity_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    router_public_key_b64: Option<String>,
    assigned_components: Vec<String>,
    artifact_dir: String,
    site_state_root: String,
    supervisor_plan_path: String,
    desired_links_path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    dynamic_external_slots: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    launch_commands: Vec<LaunchCommandPreview>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    processes: Vec<DirectLaunchProcessPreview>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    virtual_machines: Vec<VmLaunchPreview>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    inspectability_warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LaunchCommandPreview {
    argv: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    env: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    current_dir: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LaunchBundleLinkPreview {
    provider_site: String,
    provider_kind: SiteKind,
    provider_component: String,
    provide: String,
    provider_router_identity_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provider_router_mesh_port: Option<u16>,
    consumer_site: String,
    consumer_kind: SiteKind,
    consumer_component: String,
    slot: String,
    protocol: NetworkProtocol,
    export_name: String,
    external_slot_name: String,
    external_slot_env: String,
    consumer_mesh_host: String,
    resolution: LaunchBundleLinkResolution,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    preview_external_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unresolved_reason: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LaunchBundleLinkResolution {
    Exact,
    RequiresRuntimeDiscovery,
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

#[derive(Clone, Debug)]
struct MaterializedObservability {
    receipt: ObservabilityReceipt,
    plan_path: Option<PathBuf>,
}

#[derive(Clone, Debug)]
struct MaterializedSite {
    site_plan: RunSitePlan,
    artifact_dir: PathBuf,
    site_state_root: PathBuf,
    base_supervisor_plan: SiteSupervisorPlan,
}

#[derive(Clone, Debug)]
struct MaterializedLaunchBundle {
    run_plan_path: PathBuf,
    observability: Option<MaterializedObservability>,
    sites: BTreeMap<String, MaterializedSite>,
}

#[derive(Clone, Debug, Default)]
struct SiteLaunchPreviewBundle {
    router_public_key_b64: Option<String>,
    processes: Vec<DirectLaunchProcessPreview>,
    virtual_machines: Vec<VmLaunchPreview>,
    inspectability_warnings: Vec<String>,
}

#[derive(Clone, Debug)]
struct SiteStitchContext {
    kind: SiteKind,
    router_identity_id: String,
    router_public_key_b64: Option<String>,
    router_mesh_port: Option<u16>,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OutsideProxyPlan {
    schema: String,
    version: u32,
    run_root: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    slot_bindings: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    export_bindings: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OutsideProxyState {
    schema: String,
    version: u32,
    mesh_listen: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    exports: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
struct RunOutsideProxyContext {
    mesh_scope: String,
    sites: BTreeMap<String, LaunchedSite>,
    exports: BTreeMap<String, RunOutsideExport>,
    slots: BTreeMap<String, RunOutsideSlot>,
}

#[derive(Clone, Debug)]
struct RunOutsideExport {
    site_id: String,
    protocol: String,
}

#[derive(Clone, Debug)]
struct RunOutsideSlot {
    required: bool,
    kind: CapabilityKind,
    url_env: String,
    consumer_sites: Vec<String>,
}

#[derive(Clone, Debug)]
struct LaunchedSite {
    receipt: SiteReceipt,
    router_control: ControlEndpoint,
    router_identity: MeshIdentityPublic,
    router_addr: SocketAddr,
}

#[derive(Clone, Debug)]
pub(crate) struct ResolvedRunProxyTarget {
    pub(crate) artifact_dir: PathBuf,
    pub(crate) router_control_addr: Option<String>,
    pub(crate) router_addr: Option<SocketAddr>,
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

struct BridgeProxyHandle {
    child: Child,
    export_name: String,
    listen: SocketAddr,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct BridgeProxyKey {
    export_name: String,
    consumer_kind: SiteKind,
}

#[derive(Debug)]
struct SupervisorRuntime {
    site_process: Option<Child>,
    site_started: bool,
    port_forward: Option<Child>,
    last_start_attempt: Option<Instant>,
    last_stitch_refresh: Option<Instant>,
    ready_since: Option<Instant>,
}

fn site_state_from_receipt(
    receipt: &RunReceipt,
    site_id: &str,
    site: &SiteReceipt,
    status: SiteLifecycleStatus,
    last_error: Option<String>,
) -> SiteManagerState {
    let process_pid = if matches!(status, SiteLifecycleStatus::Stopped) {
        None
    } else {
        site.process_pid
    };
    let port_forward_pid = if matches!(status, SiteLifecycleStatus::Stopped) {
        None
    } else {
        site.port_forward_pid
    };
    SiteManagerState {
        schema: SITE_STATE_SCHEMA.to_string(),
        version: SITE_STATE_VERSION,
        run_id: receipt.run_id.clone(),
        site_id: site_id.to_string(),
        kind: site.kind,
        status,
        artifact_dir: site.artifact_dir.clone(),
        supervisor_pid: site.supervisor_pid,
        process_pid,
        compose_project: site.compose_project.clone(),
        kubernetes_namespace: site.kubernetes_namespace.clone(),
        port_forward_pid,
        context: site.context.clone(),
        router_control: site.router_control.clone(),
        router_mesh_addr: site.router_mesh_addr.clone(),
        router_identity_id: site.router_identity_id.clone(),
        router_public_key_b64: site.router_public_key_b64.clone(),
        last_error,
    }
}

enum SiteSupervisorStopStatus {
    Graceful { shutdown_failed: bool },
    Exited,
    TimedOut,
}

fn read_site_state_if_present(path: &Path) -> Option<SiteManagerState> {
    if !path.is_file() {
        return None;
    }
    read_json::<SiteManagerState>(path, "site state").ok()
}

async fn wait_for_site_supervisor_stop(
    state_path: &Path,
    supervisor_pid: u32,
    timeout: Duration,
) -> Result<SiteSupervisorStopStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        let state = read_site_state_if_present(state_path);
        let alive = pid_is_alive(supervisor_pid);
        if !alive {
            if state.as_ref().is_some_and(|state| {
                matches!(
                    state.status,
                    SiteLifecycleStatus::Stopped | SiteLifecycleStatus::Failed
                )
            }) {
                return Ok(SiteSupervisorStopStatus::Graceful {
                    shutdown_failed: state
                        .as_ref()
                        .is_some_and(|state| state.status == SiteLifecycleStatus::Failed),
                });
            }
            return Ok(SiteSupervisorStopStatus::Exited);
        }
        if Instant::now() >= deadline {
            return Ok(SiteSupervisorStopStatus::TimedOut);
        }
        sleep(Duration::from_millis(200)).await;
    }
}

async fn finalize_site_stop_via_orphan_cleanup(
    run_root: &Path,
    state_path: &Path,
    receipt: &RunReceipt,
    site_id: &str,
    site: &SiteReceipt,
    reason: String,
) -> Result<()> {
    stop_site_from_receipt(run_root, site_id, site).await?;
    write_site_state(
        state_path,
        site_state_from_receipt(
            receipt,
            site_id,
            site,
            SiteLifecycleStatus::Stopped,
            Some(reason),
        ),
    )
}

fn site_supervisor_stop_timeout() -> Duration {
    if cfg!(test) {
        Duration::from_secs(1)
    } else {
        SITE_SUPERVISOR_STOP_TIMEOUT
    }
}

fn forced_supervisor_exit_grace_period() -> Duration {
    if cfg!(test) {
        Duration::from_secs(1)
    } else {
        FORCED_SUPERVISOR_EXIT_GRACE_PERIOD
    }
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
        ready_since: None,
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

            let discovery =
                match try_discover_site(&plan, &mut runtime, stop_requested.as_ref(), &run_root)
                    .await
                {
                    Ok(discovery) => discovery,
                    Err(err) => {
                        runtime.ready_since = None;
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
                let ready_since = runtime.ready_since.get_or_insert_with(Instant::now);
                if ready_since.elapsed() < SITE_DISCOVERY_STABILITY_WINDOW {
                    write_site_state_if_changed(
                        &state_path,
                        &mut last_written_state,
                        build_site_state(
                            &plan,
                            &runtime,
                            SiteLifecycleStatus::Starting,
                            Some(&discovery),
                            None,
                        ),
                    )?;
                    sleep(SUPERVISOR_POLL_INTERVAL).await;
                    continue;
                }
                if should_refresh_stitching(runtime.last_stitch_refresh) {
                    let refreshed = match apply_desired_links(
                        &plan,
                        &discovery.control_endpoint,
                        stop_requested.as_ref(),
                        &run_root,
                    )
                    .await
                    {
                        Ok(refreshed) => refreshed,
                        Err(err) => {
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
                    };
                    if !refreshed {
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
                runtime.ready_since = None;
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
        if stop_requested.load(Ordering::SeqCst) {
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

fn prepare_kubernetes_artifact_namespace(
    run_id: &str,
    site_id: &str,
    artifact_dir: &Path,
) -> Result<String> {
    let namespace = kubernetes_namespace_name(run_id, site_id);
    let kustomization = artifact_dir.join("kustomization.yaml");
    let contents = fs::read_to_string(&kustomization)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", kustomization.display()))?;

    let mut saw_namespace = false;
    let mut out = String::new();
    for line in contents.lines() {
        if line.trim_start().starts_with("namespace:") {
            saw_namespace = true;
            out.push_str("namespace: ");
            out.push_str(&namespace);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    if !saw_namespace {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("namespace: ");
        out.push_str(&namespace);
        out.push('\n');
    }
    if out != contents {
        fs::write(&kustomization, out)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to update {}", kustomization.display()))?;
    }

    Ok(namespace)
}

fn kubernetes_namespace_name(run_id: &str, site_id: &str) -> String {
    let raw = format!("amber-{run_id}-{site_id}");
    let mut out = String::with_capacity(raw.len().min(63));
    let mut last_was_dash = false;

    for ch in raw.chars() {
        let next = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_lowercase()
        } else {
            '-'
        };
        if next == '-' {
            if out.is_empty() || last_was_dash {
                continue;
            }
            last_was_dash = true;
        } else {
            last_was_dash = false;
        }
        out.push(next);
        if out.len() == 63 {
            break;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "amber".to_string()
    } else {
        out
    }
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
        let host = container_host_for_consumer(SiteKind::Direct, kind);
        url.set_host(Some(&host))
            .map_err(|_| miette::miette!("failed to rewrite observability endpoint {endpoint}"))?;
    }
    Ok(url.to_string())
}

pub(crate) fn reserve_loopback_port() -> Result<u16> {
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

fn launch_bundle_manifest_path(run_root: &Path) -> PathBuf {
    run_root.join("launch-bundle.json")
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

async fn wait_for_stop_request(stop_requested: &AtomicBool, run_root: &Path) {
    loop {
        if stop_requested.load(Ordering::SeqCst) || stop_marker_path(run_root).exists() {
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }
}

async fn run_until_stop<T, F>(
    run_root: &Path,
    stop_requested: &AtomicBool,
    future: F,
) -> Result<Option<T>>
where
    F: Future<Output = Result<T>>,
{
    tokio::pin!(future);
    tokio::select! {
        result = &mut future => result.map(Some),
        _ = wait_for_stop_request(stop_requested, run_root) => Ok(None),
    }
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

fn outside_proxy_plan_path(run_root: &Path) -> PathBuf {
    run_root.join("outside-proxy-plan.json")
}

fn outside_proxy_state_path(run_root: &Path) -> PathBuf {
    run_root.join("outside-proxy-state.json")
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

pub(crate) fn read_json<T: for<'de> Deserialize<'de>>(path: &Path, label: &str) -> Result<T> {
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
        let alive = unsafe {
            libc::kill(pid as i32, 0) == 0
                || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
        };
        alive && process_status_code(pid) != Some('Z')
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

#[cfg(unix)]
fn send_sigkill(pid: u32) {
    let _ = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
}

#[cfg(unix)]
async fn shutdown_recorded_processes(site: &SiteReceipt) -> Result<()> {
    let mut roots = Vec::new();
    if let Some(pid) = site.process_pid {
        roots.push(pid);
    }
    if let Some(pid) = site.port_forward_pid {
        roots.push(pid);
    }
    terminate_recorded_processes(&roots).await
}

#[cfg(not(unix))]
async fn shutdown_recorded_processes(site: &SiteReceipt) -> Result<()> {
    if let Some(pid) = site.process_pid {
        send_sigterm(pid);
    }
    if let Some(pid) = site.port_forward_pid {
        send_sigterm(pid);
    }
    Ok(())
}

#[cfg(unix)]
async fn terminate_recorded_processes(root_pids: &[u32]) -> Result<()> {
    let mut seen = BTreeSet::new();
    let mut ordered = Vec::new();
    for root_pid in root_pids {
        for pid in process_tree_postorder(*root_pid)? {
            if seen.insert(pid) {
                ordered.push(pid);
            }
        }
    }
    if ordered.is_empty() {
        return Ok(());
    }
    for pid in &ordered {
        send_sigterm(*pid);
    }
    wait_for_pids_exit(&ordered, PROCESS_SHUTDOWN_GRACE_PERIOD).await;
    let survivors = ordered
        .iter()
        .copied()
        .filter(|pid| pid_is_alive(*pid))
        .collect::<Vec<_>>();
    for pid in &survivors {
        send_sigkill(*pid);
    }
    wait_for_pids_exit(&survivors, Duration::from_secs(2)).await;
    Ok(())
}

#[cfg(unix)]
fn process_status_code(pid: u32) -> Option<char> {
    let output = Command::new("ps")
        .arg("-o")
        .arg("stat=")
        .arg("-p")
        .arg(pid.to_string())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_process_status_code(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(unix)]
fn parse_process_status_code(raw: &str) -> Option<char> {
    raw.split_whitespace()
        .next()?
        .chars()
        .next()
        .map(|state| state.to_ascii_uppercase())
}

#[cfg(unix)]
async fn wait_for_pids_exit(pids: &[u32], timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if pids.iter().all(|pid| !pid_is_alive(*pid)) {
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(unix)]
fn process_tree_postorder(root_pid: u32) -> Result<Vec<u32>> {
    let output = Command::new("ps")
        .arg("-axo")
        .arg("pid=,ppid=")
        .output()
        .into_diagnostic()
        .wrap_err("failed to enumerate process tree")?;
    if !output.status.success() {
        return Err(miette::miette!(
            "failed to enumerate process tree: status {}",
            output.status
        ));
    }

    let parent_by_pid = parse_process_table(&String::from_utf8_lossy(&output.stdout))?;
    let mut children_by_parent = HashMap::<u32, Vec<u32>>::new();
    for (pid, ppid) in parent_by_pid {
        children_by_parent.entry(ppid).or_default().push(pid);
    }

    let mut ordered = Vec::new();
    collect_process_tree_postorder(root_pid, &children_by_parent, &mut ordered);
    Ok(ordered)
}

#[cfg(unix)]
fn collect_process_tree_postorder(
    pid: u32,
    children_by_parent: &HashMap<u32, Vec<u32>>,
    ordered: &mut Vec<u32>,
) {
    if let Some(children) = children_by_parent.get(&pid) {
        for child in children {
            collect_process_tree_postorder(*child, children_by_parent, ordered);
        }
    }
    ordered.push(pid);
}

fn parse_process_table(raw: &str) -> Result<HashMap<u32, u32>> {
    let mut parent_by_pid = HashMap::new();
    for line in raw.lines() {
        let mut fields = line.split_whitespace();
        let Some(pid) = fields.next() else {
            continue;
        };
        let Some(ppid) = fields.next() else {
            continue;
        };
        let pid = pid
            .parse::<u32>()
            .into_diagnostic()
            .wrap_err_with(|| format!("invalid process table pid `{pid}`"))?;
        let ppid = ppid
            .parse::<u32>()
            .into_diagnostic()
            .wrap_err_with(|| format!("invalid process table parent pid `{ppid}`"))?;
        parent_by_pid.insert(pid, ppid);
    }
    Ok(parent_by_pid)
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

#[cfg(test)]
mod tests;
