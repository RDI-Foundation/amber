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
    reporter::{
        direct::DirectPlan,
        vm::{VM_PLAN_FILENAME, VmPlan},
    },
    run_plan::{RunLink, RunPlan, RunSitePlan, SiteKind},
};
use amber_manifest::{CapabilityKind, CapabilityTransport, NetworkProtocol};
use amber_mesh::{
    InboundRoute, InboundTarget, MESH_CONFIG_FILENAME, MESH_IDENTITY_FILENAME, MeshConfig,
    MeshConfigPublic, MeshIdentity, MeshIdentityPublic, MeshIdentitySecret, MeshPeer, MeshProtocol,
    MeshProvisionOutput, MeshProvisionPlan, MeshProvisionTargetKind, OutboundRoute,
    TransportConfig, component_route_id, router_export_route_id,
    telemetry::{SCENARIO_RUN_ID_ENV, SCENARIO_SCOPE_ENV},
};
use amber_proxy::{
    ControlEndpoint, RouterDiscovery, apply_route_overlay_with_retry, discover_router_for_output,
    fetch_router_identity, register_export_peer_with_retry, register_external_slot_with_retry,
    revoke_route_overlay_with_retry,
};
use axum::{
    Router,
    extract::{Path as AxumPath, State},
    http::StatusCode,
    routing::{get, post},
};
use base64::Engine as _;
use miette::{Context as _, IntoDiagnostic as _, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue};
use tokio::{
    net::TcpListener as TokioTcpListener,
    sync::Mutex as AsyncMutex,
    time::{Instant, sleep},
};
use url::Url;

use crate::{
    DirectLaunchProcessPreview, DirectSiteLaunchPreview, build_direct_site_launch_preview,
    direct_current_control_socket_path,
    direct_runtime::ensure_direct_control_socket_link,
    direct_runtime_state_path,
    framework_component::{
        DynamicSitePlanRecord, SiteActuatorDestroyRequest, SiteActuatorPrepareRequest,
        SiteActuatorPublishRequest,
    },
    run_inputs::{collect_run_interface, validate_export_bindings, validate_slot_bindings},
    site_proxy_metadata::load_site_proxy_metadata,
    tcp_readiness::{wait_for_http_response, wait_for_stable_endpoint},
    vm_runtime::{
        TCG_VM_STARTUP_TIMEOUT, VmLaunchPreview, VmRuntimeState, VmSiteLaunchPreview,
        build_vm_site_launch_preview, ensure_control_socket_link, vm_current_control_socket_path,
        vm_uses_tcg_accel,
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
const SITE_ACTUATOR_PLAN_SCHEMA: &str = "amber.run.site_actuator_plan";
const SITE_ACTUATOR_PLAN_VERSION: u32 = 1;
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
    pub(crate) framework_control_state: Option<FrameworkControlStateReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) observability: Option<ObservabilityReceipt>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) bridge_proxies: Vec<BridgeProxyReceipt>,
    pub(crate) sites: BTreeMap<String, SiteReceipt>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct FrameworkControlStateReceipt {
    pub(crate) pid: u32,
    pub(crate) url: String,
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
pub(crate) struct SiteSupervisorPlan {
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    framework_ccs_plan_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    site_actuator_plan_path: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    launch_env: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SiteActuatorPlan {
    pub(crate) schema: String,
    pub(crate) version: u32,
    pub(crate) run_id: String,
    pub(crate) run_root: String,
    pub(crate) site_id: String,
    pub(crate) kind: SiteKind,
    pub(crate) router_identity_id: String,
    pub(crate) artifact_dir: String,
    pub(crate) site_state_root: String,
    pub(crate) listen_addr: SocketAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) storage_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) runtime_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) router_mesh_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) compose_project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) kubernetes_namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) observability_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) launch_env: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SiteActuatorState {
    schema: String,
    version: u32,
    run_id: String,
    site_id: String,
    kind: SiteKind,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    children: BTreeMap<u64, SiteActuatorChildRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SiteActuatorChildRecord {
    child_id: u64,
    artifact_root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    process_pid: Option<u32>,
    published: bool,
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
    framework_ccs_plan_path: Option<&'a Path>,
    site_actuator_plan_path: Option<&'a Path>,
}

#[derive(Clone, Debug)]
struct MaterializedObservability {
    receipt: ObservabilityReceipt,
    plan_path: Option<PathBuf>,
}

#[derive(Clone, Debug)]
struct MaterializedFrameworkControlState {
    plan_path: PathBuf,
    receipt: FrameworkControlStateReceipt,
}

#[derive(Clone, Debug)]
pub(crate) struct MaterializedSite {
    pub(crate) site_plan: RunSitePlan,
    pub(crate) artifact_dir: PathBuf,
    pub(crate) site_state_root: PathBuf,
    pub(crate) base_supervisor_plan: SiteSupervisorPlan,
}

#[derive(Clone, Debug)]
struct MaterializedLaunchBundle {
    run_plan_path: PathBuf,
    framework_control_state: Option<MaterializedFrameworkControlState>,
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
pub(crate) struct DesiredLinkState {
    pub(crate) schema: String,
    pub(crate) version: u32,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) external_slots: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) export_peers: Vec<DesiredExportPeer>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DesiredExportPeer {
    pub(crate) export_name: String,
    pub(crate) peer_id: String,
    pub(crate) peer_key_b64: String,
    pub(crate) protocol: String,
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
pub(crate) struct LaunchedSite {
    pub(crate) receipt: SiteReceipt,
    pub(crate) router_control: ControlEndpoint,
    pub(crate) router_identity: MeshIdentityPublic,
    pub(crate) router_addr: SocketAddr,
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

pub(crate) struct BridgeProxyHandle {
    pub(crate) child: Child,
    pub(crate) export_name: String,
    pub(crate) listen: SocketAddr,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct BridgeProxyKey {
    pub(crate) provider_output_dir: String,
    pub(crate) export_name: String,
    pub(crate) consumer_kind: SiteKind,
}

#[derive(Debug)]
struct SupervisorRuntime {
    site_process: Option<Child>,
    site_started: bool,
    port_forward: Option<Child>,
    framework_ccs: Option<Child>,
    site_actuator: Option<Child>,
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
        framework_ccs: None,
        site_actuator: None,
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

pub(crate) async fn run_site_actuator(plan_path: PathBuf) -> Result<()> {
    let plan: SiteActuatorPlan = read_json(&plan_path, "site actuator plan")?;
    let state_path = site_actuator_state_path(Path::new(&plan.site_state_root));
    let initial_state = if state_path.is_file() {
        read_json(&state_path, "site actuator state")?
    } else {
        let state = SiteActuatorState {
            schema: "amber.run.site_actuator_state".to_string(),
            version: 1,
            run_id: plan.run_id.clone(),
            site_id: plan.site_id.clone(),
            kind: plan.kind,
            children: BTreeMap::new(),
        };
        write_json(&state_path, &state)?;
        state
    };
    let app = SiteActuatorApp {
        plan,
        state_path,
        state: Arc::new(AsyncMutex::new(initial_state)),
    };
    let stop_requested = install_signal_flag();
    let listener = TokioTcpListener::bind(app.plan.listen_addr)
        .await
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to bind site actuator on {}", app.plan.listen_addr))?;
    let router = Router::new()
        .route("/healthz", get(site_actuator_healthz))
        .route(
            "/v1/children/{child_id}/prepare",
            post(site_actuator_prepare),
        )
        .route(
            "/v1/children/{child_id}/publish",
            post(site_actuator_publish),
        )
        .route(
            "/v1/children/{child_id}/rollback",
            post(site_actuator_rollback),
        )
        .route(
            "/v1/children/{child_id}/destroy",
            post(site_actuator_destroy),
        )
        .with_state(app);
    axum::serve(listener, router.into_make_service())
        .with_graceful_shutdown(async move {
            while !stop_requested.load(Ordering::SeqCst) {
                sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .into_diagnostic()
        .wrap_err("site actuator failed")
}

#[derive(Clone)]
struct SiteActuatorApp {
    plan: SiteActuatorPlan,
    state_path: PathBuf,
    state: Arc<AsyncMutex<SiteActuatorState>>,
}

type ActuatorHttpResult<T> = std::result::Result<T, (StatusCode, String)>;

async fn site_actuator_healthz() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn site_actuator_prepare(
    State(app): State<SiteActuatorApp>,
    AxumPath(child_id): AxumPath<u64>,
    axum::Json(request): axum::Json<SiteActuatorPrepareRequest>,
) -> ActuatorHttpResult<StatusCode> {
    actuator_prepare_child(&app, child_id, request.site_plan)
        .await
        .map_err(actuator_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn site_actuator_publish(
    State(app): State<SiteActuatorApp>,
    AxumPath(child_id): AxumPath<u64>,
    axum::Json(request): axum::Json<SiteActuatorPublishRequest>,
) -> ActuatorHttpResult<StatusCode> {
    actuator_publish_child(&app, child_id, request.site_plan)
        .await
        .map_err(actuator_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn site_actuator_rollback(
    State(app): State<SiteActuatorApp>,
    AxumPath(child_id): AxumPath<u64>,
) -> ActuatorHttpResult<StatusCode> {
    actuator_rollback_child(&app, child_id)
        .await
        .map_err(actuator_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn site_actuator_destroy(
    State(app): State<SiteActuatorApp>,
    AxumPath(child_id): AxumPath<u64>,
    axum::Json(request): axum::Json<SiteActuatorDestroyRequest>,
) -> ActuatorHttpResult<StatusCode> {
    actuator_destroy_child(&app, child_id, request.desired_site_plan)
        .await
        .map_err(actuator_error)?;
    Ok(StatusCode::NO_CONTENT)
}

fn actuator_error(err: miette::Report) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

fn site_actuator_state_path(site_state_root: &Path) -> PathBuf {
    site_state_root.join("site-actuator-state.json")
}

fn site_actuator_child_root(plan: &SiteActuatorPlan, child_id: u64) -> PathBuf {
    Path::new(&plan.site_state_root)
        .join("framework-component")
        .join("children")
        .join(child_id.to_string())
}

pub(super) fn site_actuator_child_root_for_site(site_state_root: &Path, child_id: u64) -> PathBuf {
    site_state_root
        .join("framework-component")
        .join("children")
        .join(child_id.to_string())
}

fn site_actuator_child_artifact_root(plan: &SiteActuatorPlan, child_id: u64) -> PathBuf {
    site_actuator_child_root(plan, child_id).join("artifact")
}

fn site_actuator_child_runtime_root(plan: &SiteActuatorPlan, child_id: u64) -> PathBuf {
    site_actuator_child_root(plan, child_id).join("runtime")
}

fn site_actuator_child_storage_root(plan: &SiteActuatorPlan, child_id: u64) -> PathBuf {
    site_actuator_child_root(plan, child_id).join("storage")
}

fn site_actuator_child_peer_ports_path(plan: &SiteActuatorPlan, child_id: u64) -> PathBuf {
    site_actuator_child_root(plan, child_id).join("existing-peer-ports.json")
}

fn site_actuator_child_peer_identities_path(plan: &SiteActuatorPlan, child_id: u64) -> PathBuf {
    site_actuator_child_root(plan, child_id).join("existing-peer-identities.json")
}

pub(super) fn cleanup_dynamic_site_children(site_state_root: &Path, kind: SiteKind) -> Result<()> {
    let state_path = site_actuator_state_path(site_state_root);
    if !state_path.is_file() {
        return Ok(());
    }
    let mut state: SiteActuatorState = read_json(&state_path, "site actuator state")?;
    for child in state.children.values() {
        if let Some(pid) = child.process_pid {
            terminate_pid(pid, site_ready_timeout_for_kind(kind))?;
        }
        remove_dir_if_exists(&site_actuator_child_root_for_site(
            site_state_root,
            child.child_id,
        ))?;
    }
    if state.children.is_empty() {
        return Ok(());
    }
    state.children.clear();
    write_json(&state_path, &state)
}

fn rewrite_dynamic_proxy_metadata(
    artifact_root: &Path,
    site_plan: &DynamicSitePlanRecord,
) -> Result<()> {
    if site_plan.proxy_exports.is_empty() {
        return Ok(());
    }
    if site_plan.kind == SiteKind::Compose {
        let path = artifact_root.join("compose.yaml");
        let raw = fs::read_to_string(&path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read {}", path.display()))?;
        let mut document: serde_yaml::Value = serde_yaml::from_str(&raw)
            .into_diagnostic()
            .wrap_err_with(|| format!("invalid compose file {}", path.display()))?;
        let Some(root) = document.as_mapping_mut() else {
            return Err(miette::miette!(
                "compose file {} is not a YAML mapping",
                path.display()
            ));
        };
        let x_amber_key = serde_yaml::Value::String("x-amber".to_string());
        let Some(x_amber) = root.get_mut(&x_amber_key) else {
            return Err(miette::miette!(
                "compose file {} is missing x-amber metadata",
                path.display()
            ));
        };
        let exports = site_plan
            .proxy_exports
            .iter()
            .map(|(name, export)| {
                (
                    serde_yaml::Value::String(name.clone()),
                    serde_yaml::Value::Mapping(serde_yaml::Mapping::from_iter([
                        (
                            serde_yaml::Value::String("component".to_string()),
                            serde_yaml::Value::String(export.component.clone()),
                        ),
                        (
                            serde_yaml::Value::String("provide".to_string()),
                            serde_yaml::Value::String(export.provide.clone()),
                        ),
                        (
                            serde_yaml::Value::String("protocol".to_string()),
                            serde_yaml::Value::String(export.protocol.clone()),
                        ),
                        (
                            serde_yaml::Value::String("router_mesh_port".to_string()),
                            serde_yaml::Value::Number(0u64.into()),
                        ),
                    ])),
                )
            })
            .collect::<serde_yaml::Mapping>();
        let mut metadata = x_amber.as_mapping().cloned().ok_or_else(|| {
            miette::miette!(
                "compose file {} has non-mapping x-amber metadata",
                path.display()
            )
        })?;
        metadata.insert(
            serde_yaml::Value::String("exports".to_string()),
            serde_yaml::Value::Mapping(exports),
        );
        *x_amber = serde_yaml::Value::Mapping(metadata);
        let rendered = serde_yaml::to_string(&document)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to serialize {}", path.display()))?;
        fs::write(&path, rendered)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to write {}", path.display()))
    } else {
        let exports = site_plan
            .proxy_exports
            .iter()
            .map(|(name, export)| {
                (
                    name.clone(),
                    JsonValue::Object(JsonMap::from_iter([
                        (
                            "component".to_string(),
                            JsonValue::String(export.component.clone()),
                        ),
                        (
                            "provide".to_string(),
                            JsonValue::String(export.provide.clone()),
                        ),
                        (
                            "protocol".to_string(),
                            JsonValue::String(export.protocol.clone()),
                        ),
                        ("router_mesh_port".to_string(), JsonValue::from(0u64)),
                    ])),
                )
            })
            .collect::<JsonMap<_, _>>();
        let path = artifact_root.join("amber-proxy.json");
        let mut metadata: JsonValue = read_json(&path, "proxy metadata")?;
        let Some(object) = metadata.as_object_mut() else {
            return Err(miette::miette!(
                "proxy metadata {} is not a JSON object",
                path.display()
            ));
        };
        object.insert("exports".to_string(), JsonValue::Object(exports));
        write_json(&path, &metadata)
    }
}

fn rewrite_dynamic_compose_proxy_metadata(
    artifact_root: &Path,
    compose_project: &str,
) -> Result<()> {
    let path = artifact_root.join("compose.yaml");
    let raw = fs::read_to_string(&path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", path.display()))?;
    let mut document: serde_yaml::Value = serde_yaml::from_str(&raw)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid compose file {}", path.display()))?;
    let Some(root) = document.as_mapping_mut() else {
        return Err(miette::miette!(
            "compose file {} is not a YAML mapping",
            path.display()
        ));
    };
    let x_amber_key = serde_yaml::Value::String("x-amber".to_string());
    let Some(x_amber) = root.get_mut(&x_amber_key) else {
        return Err(miette::miette!(
            "compose file {} is missing x-amber metadata",
            path.display()
        ));
    };
    let mut metadata: ProxyMetadata = serde_yaml::from_value(x_amber.clone())
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "compose file {} has invalid x-amber metadata",
                path.display()
            )
        })?;
    if let Some(router) = metadata.router.as_mut() {
        router.compose_project = Some(compose_project.to_string());
    }
    *x_amber = serde_yaml::to_value(&metadata)
        .into_diagnostic()
        .wrap_err("failed to serialize compose proxy metadata")?;
    let rendered = serde_yaml::to_string(&document)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to serialize {}", path.display()))?;
    fs::write(&path, rendered)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", path.display()))
}

fn read_compose_document(path: &Path) -> Result<serde_yaml::Value> {
    let raw = fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", path.display()))?;
    serde_yaml::from_str(&raw)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid compose file {}", path.display()))
}

fn read_embedded_compose_mesh_provision_plan(artifact_root: &Path) -> Result<MeshProvisionPlan> {
    let path = artifact_root.join("compose.yaml");
    let document = read_compose_document(&path)?;
    let Some(root) = document.as_mapping() else {
        return Err(miette::miette!(
            "compose file {} is not a YAML mapping",
            path.display()
        ));
    };
    let configs_key = serde_yaml::Value::String("configs".to_string());
    let config_name = serde_yaml::Value::String("amber-mesh-provision-plan".to_string());
    let content_key = serde_yaml::Value::String("content".to_string());
    let content = root
        .get(&configs_key)
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|configs| configs.get(&config_name))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|config| config.get(&content_key))
        .and_then(serde_yaml::Value::as_str)
        .ok_or_else(|| {
            miette::miette!(
                "compose file {} is missing configs.amber-mesh-provision-plan.content",
                path.display()
            )
        })?;
    serde_json::from_str(content).map_err(|err| {
        miette::miette!(
            "compose file {} has invalid embedded mesh provision plan: {err}",
            path.display()
        )
    })
}

fn write_embedded_compose_mesh_provision_plan(
    artifact_root: &Path,
    plan: &MeshProvisionPlan,
) -> Result<()> {
    let path = artifact_root.join("compose.yaml");
    let mut document = read_compose_document(&path)?;
    let Some(root) = document.as_mapping_mut() else {
        return Err(miette::miette!(
            "compose file {} is not a YAML mapping",
            path.display()
        ));
    };
    let configs_key = serde_yaml::Value::String("configs".to_string());
    let config_name = serde_yaml::Value::String("amber-mesh-provision-plan".to_string());
    let content_key = serde_yaml::Value::String("content".to_string());
    let Some(configs) = root
        .get_mut(&configs_key)
        .and_then(serde_yaml::Value::as_mapping_mut)
    else {
        return Err(miette::miette!(
            "compose file {} is missing configs",
            path.display()
        ));
    };
    let Some(config) = configs
        .get_mut(&config_name)
        .and_then(serde_yaml::Value::as_mapping_mut)
    else {
        return Err(miette::miette!(
            "compose file {} is missing configs.amber-mesh-provision-plan",
            path.display()
        ));
    };
    config.insert(
        content_key,
        serde_yaml::Value::String(
            serde_json::to_string(plan)
                .map_err(|err| miette::miette!("failed to serialize mesh provision plan: {err}"))?,
        ),
    );
    let rendered = serde_yaml::to_string(&document)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to serialize {}", path.display()))?;
    fs::write(&path, rendered)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", path.display()))
}

fn upsert_mesh_peer_template(
    peers: &mut Vec<amber_mesh::MeshPeerTemplate>,
    peer: amber_mesh::MeshPeerTemplate,
) {
    if let Some(existing) = peers.iter_mut().find(|existing| existing.id == peer.id) {
        *existing = peer;
        return;
    }
    peers.push(peer);
}

fn upsert_inbound_route(routes: &mut Vec<InboundRoute>, route: InboundRoute) {
    if let Some(existing) = routes
        .iter_mut()
        .find(|existing| existing.route_id == route.route_id)
    {
        *existing = route;
        return;
    }
    routes.push(route);
}

fn compose_mesh_service_name(target: &amber_mesh::MeshProvisionTarget) -> Result<String> {
    let MeshProvisionOutput::Filesystem { dir } = &target.output else {
        return Err(miette::miette!(
            "compose mesh target {} does not use filesystem output",
            target.config.identity.id
        ));
    };
    Path::new(dir)
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string)
        .ok_or_else(|| {
            miette::miette!(
                "compose mesh target {} has invalid output dir {}",
                target.config.identity.id,
                dir
            )
        })
}

fn parse_mesh_peer_port(peer_addr: &str) -> Result<u16> {
    peer_addr
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .ok_or_else(|| miette::miette!("invalid mesh peer address `{peer_addr}`"))
}

fn patch_dynamic_compose_site_mesh_plan(
    site_artifact_root: &Path,
    child_artifact_root: &Path,
) -> Result<()> {
    let mut site_plan = read_embedded_compose_mesh_provision_plan(site_artifact_root)?;
    let child_plan = read_embedded_compose_mesh_provision_plan(child_artifact_root)?;
    let Some(site_router_index) = site_plan
        .targets
        .iter()
        .position(|target| matches!(target.kind, MeshProvisionTargetKind::Router))
    else {
        return Err(miette::miette!(
            "compose site artifact {} is missing a router target",
            site_artifact_root.display()
        ));
    };
    let site_mesh_service_by_peer_id = site_plan
        .targets
        .iter()
        .filter(|target| matches!(target.kind, MeshProvisionTargetKind::Component))
        .map(|target| {
            compose_mesh_service_name(target)
                .map(|service_name| (target.config.identity.id.clone(), service_name))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;

    for child_target in child_plan
        .targets
        .iter()
        .filter(|target| matches!(target.kind, MeshProvisionTargetKind::Component))
    {
        let Some(site_target) = site_plan.targets.iter_mut().find(|target| {
            matches!(target.kind, MeshProvisionTargetKind::Component)
                && target.config.identity.id == child_target.config.identity.id
        }) else {
            return Err(miette::miette!(
                "compose site artifact {} is missing component target {}",
                site_artifact_root.display(),
                child_target.config.identity.id
            ));
        };
        for peer in child_target.config.peers.iter().cloned() {
            upsert_mesh_peer_template(&mut site_target.config.peers, peer);
        }
        for route in child_target.config.inbound.iter().cloned() {
            upsert_inbound_route(&mut site_target.config.inbound, route);
        }
    }

    let child_router = child_plan
        .targets
        .iter()
        .find(|target| matches!(target.kind, MeshProvisionTargetKind::Router))
        .ok_or_else(|| {
            miette::miette!(
                "compose child artifact {} is missing a router target",
                child_artifact_root.display()
            )
        })?
        .clone();
    let site_router = &mut site_plan.targets[site_router_index];
    for peer in child_router.config.peers {
        upsert_mesh_peer_template(&mut site_router.config.peers, peer);
    }
    for mut route in child_router.config.inbound {
        if let InboundTarget::MeshForward {
            peer_id, peer_addr, ..
        } = &mut route.target
        {
            let port = parse_mesh_peer_port(peer_addr)?;
            *peer_addr = format!(
                "{}:{port}",
                site_mesh_service_by_peer_id
                    .get(peer_id)
                    .cloned()
                    .ok_or_else(|| {
                        miette::miette!(
                            "compose site artifact {} is missing a mesh service for {}",
                            site_artifact_root.display(),
                            peer_id
                        )
                    })?
            );
        }
        upsert_inbound_route(&mut site_router.config.inbound, route);
    }
    write_embedded_compose_mesh_provision_plan(site_artifact_root, &site_plan)
}

fn project_dynamic_child_mesh_scope(artifact_root: &Path, mesh_scope: Option<&str>) -> Result<()> {
    let Some(mesh_scope) = mesh_scope else {
        return Ok(());
    };
    let path = artifact_root.join("mesh-provision-plan.json");
    let mut plan: MeshProvisionPlan = read_json(&path, "mesh provision plan")?;
    let mut changed = false;
    for target in &mut plan.targets {
        if target.config.identity.mesh_scope.as_deref() == Some(mesh_scope) {
            continue;
        }
        target.config.identity.mesh_scope = Some(mesh_scope.to_string());
        changed = true;
    }
    if !changed {
        return Ok(());
    }
    write_json(&path, &plan)
}

fn reconcile_artifact_files(site_plan: &DynamicSitePlanRecord) -> &BTreeMap<String, String> {
    if site_plan.desired_artifact_files.is_empty() {
        &site_plan.artifact_files
    } else {
        &site_plan.desired_artifact_files
    }
}

fn reconcile_site_proxy_metadata(
    site_artifact_root: &Path,
    site_plan: &DynamicSitePlanRecord,
) -> Result<()> {
    let Some(proxy_metadata) = reconcile_artifact_files(site_plan).get("amber-proxy.json") else {
        return Ok(());
    };
    let path = site_artifact_root.join("amber-proxy.json");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(&path, proxy_metadata)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", path.display()))
}

fn project_dynamic_direct_router_surface(
    plan: &SiteActuatorPlan,
    child: &SiteActuatorChildRecord,
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
        let mut state: crate::direct_runtime::DirectRuntimeState =
            read_json(&state_path, "direct runtime state")?;
        if state.router_mesh_port == Some(router_mesh_port) {
            break;
        }
        state.router_mesh_port = Some(router_mesh_port);
        write_json(&state_path, &state)?;
        std::thread::sleep(Duration::from_millis(100));
        let state: crate::direct_runtime::DirectRuntimeState =
            read_json(&state_path, "direct runtime state")?;
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

fn project_dynamic_vm_router_surface(
    plan: &SiteActuatorPlan,
    child: &SiteActuatorChildRecord,
) -> Result<()> {
    let state_path = Path::new(&child.artifact_root)
        .join(".amber")
        .join("vm-runtime.json");
    let router_mesh_port = plan.router_mesh_port.ok_or_else(|| {
        miette::miette!("vm site `{}` is missing its router mesh port", plan.site_id)
    })?;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let mut state: VmRuntimeState = read_json(&state_path, "vm runtime state")?;
        if state.router_mesh_port == Some(router_mesh_port) {
            break;
        }
        state.router_mesh_port = Some(router_mesh_port);
        write_json(&state_path, &state)?;
        std::thread::sleep(Duration::from_millis(100));
        let state: VmRuntimeState = read_json(&state_path, "vm runtime state")?;
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

fn dynamic_child_route_overlay_id(plan: &SiteActuatorPlan, child_id: u64) -> String {
    format!("framework-child:{}:{child_id}", plan.site_id)
}

fn site_router_control_endpoint(plan: &SiteActuatorPlan) -> Result<ControlEndpoint> {
    match plan.kind {
        SiteKind::Direct => Ok(ControlEndpoint::Unix(direct_current_control_socket_path(
            Path::new(&plan.artifact_dir),
        ))),
        SiteKind::Vm => Ok(ControlEndpoint::Unix(vm_current_control_socket_path(
            Path::new(&plan.artifact_dir),
        ))),
        SiteKind::Compose | SiteKind::Kubernetes => Err(miette::miette!(
            "site `{}` does not expose a local unix router control endpoint",
            plan.site_id
        )),
    }
}

fn child_router_overlay_payload(
    artifact_root: &Path,
    runtime_root: &Path,
) -> Result<(Vec<MeshPeer>, Vec<InboundRoute>)> {
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
    let mut peers = Vec::new();
    let mut peer_addr_by_id = BTreeMap::new();
    for peer in &router_target.config.peers {
        let component_target = provision
            .targets
            .iter()
            .find(|target| {
                matches!(target.kind, MeshProvisionTargetKind::Component)
                    && target.config.identity.id == peer.id
            })
            .ok_or_else(|| {
                miette::miette!(
                    "router overlay peer {} is missing from mesh provision plan",
                    peer.id
                )
            })?;
        let MeshProvisionOutput::Filesystem { dir } = &component_target.output else {
            return Err(miette::miette!(
                "router overlay peer {} does not use filesystem mesh output",
                peer.id
            ));
        };
        let identity: MeshIdentitySecret = read_json(
            &runtime_root.join(dir).join(MESH_IDENTITY_FILENAME),
            "mesh identity",
        )?;
        let runtime_config: MeshConfigPublic = read_json(
            &runtime_root.join(dir).join(MESH_CONFIG_FILENAME),
            "mesh config",
        )?;
        let public_key = identity.public_key().into_diagnostic()?;
        peer_addr_by_id.insert(
            runtime_config.identity.id.clone(),
            runtime_config.mesh_listen,
        );
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
            *peer_addr = resolved.to_string();
        }
    }
    Ok((peers, inbound_routes))
}

async fn apply_dynamic_site_router_overlay(
    plan: &SiteActuatorPlan,
    child_id: u64,
    artifact_root: &Path,
    runtime_root: &Path,
) -> Result<()> {
    let (peers, inbound_routes) = child_router_overlay_payload(artifact_root, runtime_root)?;
    if inbound_routes.is_empty() {
        return Ok(());
    }
    let endpoint = site_router_control_endpoint(plan)?;
    apply_route_overlay_with_retry(
        &endpoint,
        &dynamic_child_route_overlay_id(plan, child_id),
        &peers,
        &inbound_routes,
        Duration::from_secs(30),
    )
    .await
}

async fn revoke_dynamic_site_router_overlay(plan: &SiteActuatorPlan, child_id: u64) -> Result<()> {
    let endpoint = site_router_control_endpoint(plan)?;
    revoke_route_overlay_with_retry(
        &endpoint,
        &dynamic_child_route_overlay_id(plan, child_id),
        Duration::from_secs(30),
    )
    .await
}

async fn actuator_prepare_child(
    app: &SiteActuatorApp,
    child_id: u64,
    site_plan: DynamicSitePlanRecord,
) -> Result<()> {
    let artifact_root = site_actuator_child_artifact_root(&app.plan, child_id);
    replace_artifact_snapshot(&artifact_root, &site_plan.artifact_files)?;
    if site_plan.kind == SiteKind::Kubernetes {
        let _ = prepare_kubernetes_artifact_namespace(
            &app.plan.run_id,
            &app.plan.site_id,
            &artifact_root,
        )?;
    }
    patch_site_artifacts(
        &artifact_root,
        site_plan.kind,
        &app.plan.launch_env,
        app.plan.observability_endpoint.as_deref(),
    )?;
    match site_plan.kind {
        SiteKind::Direct => filter_direct_stage_plan(&artifact_root, &site_plan.component_ids)?,
        SiteKind::Vm => filter_vm_stage_plan(&artifact_root, &site_plan.component_ids)?,
        SiteKind::Compose | SiteKind::Kubernetes => {}
    }
    rewrite_dynamic_proxy_metadata(&artifact_root, &site_plan)?;
    if site_plan.kind == SiteKind::Compose
        && let Some(compose_project) = app.plan.compose_project.as_deref()
    {
        rewrite_dynamic_compose_proxy_metadata(&artifact_root, compose_project)?;
    }
    let mut state = app.state.lock().await;
    state.children.insert(
        child_id,
        SiteActuatorChildRecord {
            child_id,
            artifact_root: artifact_root.display().to_string(),
            process_pid: None,
            published: false,
        },
    );
    write_json(&app.state_path, &*state)
}

async fn actuator_publish_child(
    app: &SiteActuatorApp,
    child_id: u64,
    site_plan: DynamicSitePlanRecord,
) -> Result<()> {
    let child = {
        let state = app.state.lock().await;
        state
            .children
            .get(&child_id)
            .cloned()
            .ok_or_else(|| miette::miette!("site actuator child {child_id} is not prepared"))?
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
                &site_actuator_child_peer_ports_path(&app.plan, child_id),
                &existing_peer_ports,
            )?;
            write_json(
                &site_actuator_child_peer_identities_path(&app.plan, child_id),
                &existing_peer_identities,
            )?;
            project_dynamic_child_mesh_scope(
                Path::new(&child.artifact_root),
                existing_peer_identities
                    .get(&app.plan.router_identity_id)
                    .and_then(|identity| identity.mesh_scope.as_deref()),
            )?;
            let runtime_root = site_actuator_child_runtime_root(&app.plan, child_id);
            let storage_root = site_actuator_child_storage_root(&app.plan, child_id);
            let child_root = site_actuator_child_root(&app.plan, child_id);
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
                    .arg(site_actuator_child_peer_ports_path(&app.plan, child_id))
                    .arg("--existing-peer-identities")
                    .arg(site_actuator_child_peer_identities_path(
                        &app.plan, child_id,
                    ))
                    .arg("--skip-router");
            })?;
            wait_for_detached_child_runtime_state(
                process.id(),
                &direct_runtime_state_path(Path::new(&child.artifact_root)),
                site_ready_timeout_for_kind(SiteKind::Direct),
                &child_root.join("site.log"),
            )
            .await?;
            let mut state = app.state.lock().await;
            {
                let record = state
                    .children
                    .get_mut(&child_id)
                    .expect("prepared child should remain present");
                record.process_pid = Some(process.id());
            }
            write_json(&app.state_path, &*state)?;
            drop(state);
            project_dynamic_direct_router_surface(&app.plan, &child)?;
            apply_dynamic_site_router_overlay(
                &app.plan,
                child_id,
                Path::new(&child.artifact_root),
                &runtime_root,
            )
            .await?;
            reconcile_site_proxy_metadata(Path::new(&app.plan.artifact_dir), &site_plan)?;
            let mut state = app.state.lock().await;
            let record = state
                .children
                .get_mut(&child_id)
                .expect("prepared child should remain present");
            record.published = true;
            write_json(&app.state_path, &*state)?;
        }
        SiteKind::Vm => {
            let state = app.state.lock().await;
            let existing_peer_ports = local_vm_peer_ports(&app.plan, &state)?;
            let existing_peer_identities = local_vm_peer_identities(&app.plan, &state)?;
            drop(state);
            write_json(
                &site_actuator_child_peer_ports_path(&app.plan, child_id),
                &existing_peer_ports,
            )?;
            write_json(
                &site_actuator_child_peer_identities_path(&app.plan, child_id),
                &existing_peer_identities,
            )?;
            project_dynamic_child_mesh_scope(
                Path::new(&child.artifact_root),
                existing_peer_identities
                    .get(&app.plan.router_identity_id)
                    .and_then(|identity| identity.mesh_scope.as_deref()),
            )?;
            let runtime_root = site_actuator_child_runtime_root(&app.plan, child_id);
            let storage_root = site_actuator_child_storage_root(&app.plan, child_id);
            let child_root = site_actuator_child_root(&app.plan, child_id);
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
                    .arg(site_actuator_child_peer_ports_path(&app.plan, child_id))
                    .arg("--existing-peer-identities")
                    .arg(site_actuator_child_peer_identities_path(
                        &app.plan, child_id,
                    ))
                    .arg("--skip-router");
            })?;
            wait_for_detached_child_runtime_state(
                process.id(),
                &Path::new(&child.artifact_root)
                    .join(".amber")
                    .join("vm-runtime.json"),
                site_ready_timeout_for_kind(SiteKind::Vm),
                &child_root.join("site.log"),
            )
            .await?;
            let mut state = app.state.lock().await;
            {
                let record = state
                    .children
                    .get_mut(&child_id)
                    .expect("prepared child should remain present");
                record.process_pid = Some(process.id());
            }
            write_json(&app.state_path, &*state)?;
            drop(state);
            project_dynamic_vm_router_surface(&app.plan, &child)?;
            apply_dynamic_site_router_overlay(
                &app.plan,
                child_id,
                Path::new(&child.artifact_root),
                &runtime_root,
            )
            .await?;
            reconcile_site_proxy_metadata(Path::new(&app.plan.artifact_dir), &site_plan)?;
            let mut state = app.state.lock().await;
            let record = state
                .children
                .get_mut(&child_id)
                .expect("prepared child should remain present");
            record.published = true;
            write_json(&app.state_path, &*state)?;
        }
        SiteKind::Compose => {
            replace_artifact_snapshot(
                Path::new(&app.plan.artifact_dir),
                reconcile_artifact_files(&site_plan),
            )?;
            patch_dynamic_compose_site_mesh_plan(
                Path::new(&app.plan.artifact_dir),
                Path::new(&child.artifact_root),
            )?;
            let status = compose_command(
                app.plan.compose_project.as_deref(),
                Path::new(&app.plan.artifact_dir),
            )
            .envs(app.plan.launch_env.clone())
            .arg("up")
            .arg("-d")
            .arg("--remove-orphans")
            .status()
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to publish compose site `{}`", app.plan.site_id))?;
            if !status.success() {
                return Err(miette::miette!(
                    "compose site `{}` publish failed with status {status}",
                    app.plan.site_id
                ));
            }
            let mut state = app.state.lock().await;
            let record = state
                .children
                .get_mut(&child_id)
                .expect("prepared child should remain present");
            record.published = true;
            write_json(&app.state_path, &*state)?;
        }
        SiteKind::Kubernetes => {
            replace_artifact_snapshot(
                Path::new(&app.plan.artifact_dir),
                reconcile_artifact_files(&site_plan),
            )?;
            let supervisor_plan = prepare_kubernetes_site_artifact_for_apply(&app.plan)?;
            ensure_kubernetes_namespace(&supervisor_plan)?;
            let status = kubectl_command(app.plan.context.as_deref())
                .current_dir(&app.plan.artifact_dir)
                .arg("apply")
                .arg("-k")
                .arg(".")
                .arg("--prune")
                .arg("-l")
                .arg("app.kubernetes.io/managed-by=amber")
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
            let mut state = app.state.lock().await;
            let record = state
                .children
                .get_mut(&child_id)
                .expect("prepared child should remain present");
            record.published = true;
            write_json(&app.state_path, &*state)?;
        }
    }

    Ok(())
}

async fn actuator_rollback_child(app: &SiteActuatorApp, child_id: u64) -> Result<()> {
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
    remove_dir_if_exists(&site_actuator_child_root(&app.plan, child_id))
}

async fn actuator_destroy_child(
    app: &SiteActuatorApp,
    child_id: u64,
    desired_site_plan: Option<DynamicSitePlanRecord>,
) -> Result<()> {
    let child = {
        let state = app.state.lock().await;
        state.children.get(&child_id).cloned()
    };
    if child.as_ref().is_some_and(|child| child.published)
        && matches!(app.plan.kind, SiteKind::Direct | SiteKind::Vm)
    {
        revoke_dynamic_site_router_overlay(&app.plan, child_id).await?;
    }
    if let Some(child) = child
        && let Some(pid) = child.process_pid
    {
        terminate_pid(pid, site_ready_timeout_for_kind(app.plan.kind))?;
    }

    match app.plan.kind {
        SiteKind::Compose => {
            let desired = desired_site_plan.ok_or_else(|| {
                miette::miette!(
                    "compose destroy for site `{}` is missing the desired site snapshot",
                    app.plan.site_id
                )
            })?;
            replace_artifact_snapshot(Path::new(&app.plan.artifact_dir), &desired.artifact_files)?;
            patch_site_artifacts(
                Path::new(&app.plan.artifact_dir),
                app.plan.kind,
                &app.plan.launch_env,
                app.plan.observability_endpoint.as_deref(),
            )?;
            let status = compose_command(
                app.plan.compose_project.as_deref(),
                Path::new(&app.plan.artifact_dir),
            )
            .envs(app.plan.launch_env.clone())
            .arg("up")
            .arg("-d")
            .arg("--remove-orphans")
            .status()
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to reconcile compose site `{}`", app.plan.site_id))?;
            if !status.success() {
                return Err(miette::miette!(
                    "compose site `{}` reconcile failed with status {status}",
                    app.plan.site_id
                ));
            }
        }
        SiteKind::Kubernetes => {
            let desired = desired_site_plan.ok_or_else(|| {
                miette::miette!(
                    "kubernetes destroy for site `{}` is missing the desired site snapshot",
                    app.plan.site_id
                )
            })?;
            replace_artifact_snapshot(Path::new(&app.plan.artifact_dir), &desired.artifact_files)?;
            let _ = prepare_kubernetes_site_artifact_for_apply(&app.plan)?;
            let status = kubectl_command(app.plan.context.as_deref())
                .current_dir(&app.plan.artifact_dir)
                .arg("apply")
                .arg("-k")
                .arg(".")
                .arg("--prune")
                .arg("-l")
                .arg("app.kubernetes.io/managed-by=amber")
                .status()
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!("failed to reconcile kubernetes site `{}`", app.plan.site_id)
                })?;
            if !status.success() {
                return Err(miette::miette!(
                    "kubernetes site `{}` reconcile failed with status {status}",
                    app.plan.site_id
                ));
            }
        }
        SiteKind::Direct | SiteKind::Vm => {
            if let Some(desired) = desired_site_plan.as_ref() {
                reconcile_site_proxy_metadata(Path::new(&app.plan.artifact_dir), desired)?;
            }
        }
    }

    let mut state = app.state.lock().await;
    state.children.remove(&child_id);
    write_json(&app.state_path, &*state)?;
    remove_dir_if_exists(&site_actuator_child_root(&app.plan, child_id))
}

fn replace_artifact_snapshot(root: &Path, files: &BTreeMap<String, String>) -> Result<()> {
    fs::create_dir_all(root)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create {}", root.display()))?;
    let expected = files.keys().map(PathBuf::from).collect::<BTreeSet<_>>();
    for path in walk_files(root)? {
        let relative = path
            .strip_prefix(root)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to relativize {}", path.display()))?
            .to_path_buf();
        if !expected.contains(&relative) {
            fs::remove_file(&path)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to remove stale artifact {}", path.display()))?;
        }
    }
    for (relative, contents) in files {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(&path, contents)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to write {}", path.display()))?;
    }
    Ok(())
}

fn filter_direct_stage_plan(artifact_root: &Path, component_ids: &[usize]) -> Result<()> {
    let keep = component_ids.iter().copied().collect::<BTreeSet<_>>();
    let plan_path = artifact_root.join("direct-plan.json");
    let mut plan: DirectPlan = read_json(&plan_path, "direct plan")?;
    plan.components
        .retain(|component| keep.contains(&component.id));
    plan.startup_order
        .retain(|component_id| keep.contains(component_id));
    plan.router = None;
    write_json(&plan_path, &plan)
}

fn filter_vm_stage_plan(artifact_root: &Path, component_ids: &[usize]) -> Result<()> {
    let keep = component_ids.iter().copied().collect::<BTreeSet<_>>();
    let plan_path = artifact_root.join("vm-plan.json");
    let mut plan: VmPlan = read_json(&plan_path, "vm plan")?;
    plan.components
        .retain(|component| keep.contains(&component.id));
    plan.startup_order
        .retain(|component_id| keep.contains(component_id));
    plan.router = None;
    write_json(&plan_path, &plan)
}

async fn wait_for_detached_child_runtime_state(
    pid: u32,
    state_path: &Path,
    timeout: Duration,
    log_path: &Path,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if state_path.is_file() {
            return Ok(());
        }
        if !pid_is_alive(pid) {
            let log = fs::read_to_string(log_path).unwrap_or_default();
            return Err(miette::miette!(
                "dynamic child runtime exited before becoming ready\nlog ({}):\n{}",
                log_path.display(),
                log
            ));
        }
        sleep(Duration::from_millis(100)).await;
    }
    let log = fs::read_to_string(log_path).unwrap_or_default();
    Err(miette::miette!(
        "timed out waiting for dynamic child runtime state {}\nlog ({}):\n{}",
        state_path.display(),
        log_path.display(),
        log
    ))
}

fn local_direct_peer_ports(
    plan: &SiteActuatorPlan,
    state: &SiteActuatorState,
) -> Result<BTreeMap<String, u16>> {
    let site_runtime_root = Path::new(plan.runtime_root.as_deref().ok_or_else(|| {
        miette::miette!("direct site `{}` is missing its runtime root", plan.site_id)
    })?);
    let mut peers = BTreeMap::new();
    peers.insert(
        plan.router_identity_id.clone(),
        plan.router_mesh_port.ok_or_else(|| {
            miette::miette!(
                "direct site `{}` is missing its router mesh port",
                plan.site_id
            )
        })?,
    );
    peers.extend(direct_peer_ports_for_artifact(
        Path::new(&plan.artifact_dir),
        site_runtime_root,
    )?);
    for child in state.children.values().filter(|child| child.published) {
        peers.extend(direct_peer_ports_for_artifact(
            Path::new(&child.artifact_root),
            &site_actuator_child_runtime_root(plan, child.child_id),
        )?);
    }
    Ok(peers)
}

fn local_direct_peer_identities(
    plan: &SiteActuatorPlan,
    state: &SiteActuatorState,
) -> Result<BTreeMap<String, MeshIdentityPublic>> {
    let site_runtime_root = Path::new(plan.runtime_root.as_deref().ok_or_else(|| {
        miette::miette!("direct site `{}` is missing its runtime root", plan.site_id)
    })?);
    let mut peers = BTreeMap::new();
    let router =
        direct_router_identity_for_artifact(Path::new(&plan.artifact_dir), site_runtime_root)?
            .ok_or_else(|| {
                miette::miette!(
                    "direct site `{}` is missing its live router identity",
                    plan.site_id
                )
            })?;
    peers.insert(router.id.clone(), router);
    peers.extend(direct_peer_identities_for_artifact(
        Path::new(&plan.artifact_dir),
        site_runtime_root,
    )?);
    for child in state.children.values().filter(|child| child.published) {
        peers.extend(direct_peer_identities_for_artifact(
            Path::new(&child.artifact_root),
            &site_actuator_child_runtime_root(plan, child.child_id),
        )?);
    }
    Ok(peers)
}

fn direct_peer_ports_for_artifact(
    artifact_root: &Path,
    runtime_root: &Path,
) -> Result<BTreeMap<String, u16>> {
    let state: crate::direct_runtime::DirectRuntimeState = read_json(
        &direct_runtime_state_path(artifact_root),
        "direct runtime state",
    )?;
    let plan: DirectPlan = read_json(&artifact_root.join("direct-plan.json"), "direct plan")?;
    let mut peers = BTreeMap::new();
    for component in &plan.components {
        let config: MeshConfigPublic = read_json(
            &runtime_root.join(&component.sidecar.mesh_config_path),
            "mesh config",
        )?;
        let port = state
            .component_mesh_port_by_id
            .get(&component.id)
            .copied()
            .ok_or_else(|| {
                miette::miette!(
                    "direct runtime state is missing mesh port for component {}",
                    component.moniker
                )
            })?;
        peers.insert(config.identity.id, port);
    }
    Ok(peers)
}

fn direct_peer_identities_for_artifact(
    artifact_root: &Path,
    runtime_root: &Path,
) -> Result<BTreeMap<String, MeshIdentityPublic>> {
    let plan: DirectPlan = read_json(&artifact_root.join("direct-plan.json"), "direct plan")?;
    let mut peers = BTreeMap::new();
    for component in &plan.components {
        let config: MeshConfigPublic = read_json(
            &runtime_root.join(&component.sidecar.mesh_config_path),
            "mesh config",
        )?;
        peers.insert(config.identity.id.clone(), config.identity);
    }
    Ok(peers)
}

fn direct_router_identity_for_artifact(
    artifact_root: &Path,
    runtime_root: &Path,
) -> Result<Option<MeshIdentityPublic>> {
    let plan: DirectPlan = read_json(&artifact_root.join("direct-plan.json"), "direct plan")?;
    let Some(router) = plan.router.as_ref() else {
        return Ok(None);
    };
    let config: MeshConfigPublic =
        read_json(&runtime_root.join(&router.mesh_config_path), "mesh config")?;
    Ok(Some(config.identity))
}

fn local_vm_peer_ports(
    plan: &SiteActuatorPlan,
    state: &SiteActuatorState,
) -> Result<BTreeMap<String, u16>> {
    let site_runtime_root = Path::new(plan.runtime_root.as_deref().ok_or_else(|| {
        miette::miette!("vm site `{}` is missing its runtime root", plan.site_id)
    })?);
    let mut peers = BTreeMap::new();
    peers.insert(
        plan.router_identity_id.clone(),
        plan.router_mesh_port.ok_or_else(|| {
            miette::miette!("vm site `{}` is missing its router mesh port", plan.site_id)
        })?,
    );
    peers.extend(vm_peer_ports_for_artifact(
        Path::new(&plan.artifact_dir),
        site_runtime_root,
    )?);
    for child in state.children.values().filter(|child| child.published) {
        peers.extend(vm_peer_ports_for_artifact(
            Path::new(&child.artifact_root),
            &site_actuator_child_runtime_root(plan, child.child_id),
        )?);
    }
    Ok(peers)
}

fn local_vm_peer_identities(
    plan: &SiteActuatorPlan,
    state: &SiteActuatorState,
) -> Result<BTreeMap<String, MeshIdentityPublic>> {
    let site_runtime_root = Path::new(plan.runtime_root.as_deref().ok_or_else(|| {
        miette::miette!("vm site `{}` is missing its runtime root", plan.site_id)
    })?);
    let mut peers = BTreeMap::new();
    let router = vm_router_identity_for_artifact(Path::new(&plan.artifact_dir), site_runtime_root)?
        .ok_or_else(|| {
            miette::miette!(
                "vm site `{}` is missing its live router identity",
                plan.site_id
            )
        })?;
    peers.insert(router.id.clone(), router);
    peers.extend(vm_peer_identities_for_artifact(
        Path::new(&plan.artifact_dir),
        site_runtime_root,
    )?);
    for child in state.children.values().filter(|child| child.published) {
        peers.extend(vm_peer_identities_for_artifact(
            Path::new(&child.artifact_root),
            &site_actuator_child_runtime_root(plan, child.child_id),
        )?);
    }
    Ok(peers)
}

fn vm_peer_ports_for_artifact(
    artifact_root: &Path,
    runtime_root: &Path,
) -> Result<BTreeMap<String, u16>> {
    let state: VmRuntimeState = read_json(
        &artifact_root.join(".amber").join("vm-runtime.json"),
        "vm runtime state",
    )?;
    let plan: VmPlan = read_json(&artifact_root.join("vm-plan.json"), "vm plan")?;
    let mut peers = BTreeMap::new();
    for component in &plan.components {
        let config: MeshConfigPublic = read_json(
            &runtime_root.join(&component.mesh_config_path),
            "mesh config",
        )?;
        let port = state
            .component_mesh_port_by_id
            .get(&component.id)
            .copied()
            .ok_or_else(|| {
                miette::miette!(
                    "vm runtime state is missing mesh port for component {}",
                    component.moniker
                )
            })?;
        peers.insert(config.identity.id, port);
    }
    Ok(peers)
}

fn vm_peer_identities_for_artifact(
    artifact_root: &Path,
    runtime_root: &Path,
) -> Result<BTreeMap<String, MeshIdentityPublic>> {
    let plan: VmPlan = read_json(&artifact_root.join("vm-plan.json"), "vm plan")?;
    let mut peers = BTreeMap::new();
    for component in &plan.components {
        let config: MeshConfigPublic = read_json(
            &runtime_root.join(&component.mesh_config_path),
            "mesh config",
        )?;
        peers.insert(config.identity.id.clone(), config.identity);
    }
    Ok(peers)
}

fn vm_router_identity_for_artifact(
    artifact_root: &Path,
    runtime_root: &Path,
) -> Result<Option<MeshIdentityPublic>> {
    let plan: VmPlan = read_json(&artifact_root.join("vm-plan.json"), "vm plan")?;
    let Some(router) = plan.router.as_ref() else {
        return Ok(None);
    };
    let config: MeshConfigPublic =
        read_json(&runtime_root.join(&router.mesh_config_path), "mesh config")?;
    Ok(Some(config.identity))
}

fn terminate_pid(pid: u32, timeout: Duration) -> Result<()> {
    send_sigterm(pid);
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !pid_is_alive(pid) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    #[cfg(unix)]
    {
        let _ = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    }
    Ok(())
}

fn remove_dir_if_exists(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    fs::remove_dir_all(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to remove {}", path.display()))
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

fn site_supervisor_plan_for_actuator(
    plan: &SiteActuatorPlan,
    kubernetes_namespace: Option<String>,
) -> SiteSupervisorPlan {
    SiteSupervisorPlan {
        schema: SITE_PLAN_SCHEMA.to_string(),
        version: SITE_PLAN_VERSION,
        run_id: plan.run_id.clone(),
        mesh_scope: String::new(),
        run_root: plan.run_root.clone(),
        coordinator_pid: 0,
        site_id: plan.site_id.clone(),
        kind: plan.kind,
        artifact_dir: plan.artifact_dir.clone(),
        site_state_root: plan.site_state_root.clone(),
        storage_root: plan.storage_root.clone(),
        runtime_root: plan.runtime_root.clone(),
        router_mesh_port: plan.router_mesh_port,
        compose_project: plan.compose_project.clone(),
        kubernetes_namespace,
        context: plan.context.clone(),
        port_forward_mesh_port: None,
        port_forward_control_port: None,
        observability_endpoint: plan.observability_endpoint.clone(),
        framework_ccs_plan_path: None,
        site_actuator_plan_path: None,
        launch_env: plan.launch_env.clone(),
    }
}

fn prepare_kubernetes_site_artifact_for_apply(
    plan: &SiteActuatorPlan,
) -> Result<SiteSupervisorPlan> {
    debug_assert_eq!(plan.kind, SiteKind::Kubernetes);
    let namespace = prepare_kubernetes_artifact_namespace(
        &plan.run_id,
        &plan.site_id,
        Path::new(&plan.artifact_dir),
    )?;
    patch_site_artifacts(
        Path::new(&plan.artifact_dir),
        plan.kind,
        &plan.launch_env,
        plan.observability_endpoint.as_deref(),
    )?;
    Ok(site_supervisor_plan_for_actuator(plan, Some(namespace)))
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

pub(crate) fn site_state_path(state_root: &Path, site_id: &str) -> PathBuf {
    state_root.join(site_id).join("manager-state.json")
}

fn state_path_for_plan(plan: &SiteSupervisorPlan) -> PathBuf {
    Path::new(&plan.site_state_root).join("manager-state.json")
}

fn site_supervisor_plan_path(site_state_root: &Path) -> PathBuf {
    site_state_root.join("site-supervisor-plan.json")
}

fn site_actuator_plan_path(site_state_root: &Path) -> PathBuf {
    site_state_root.join("site-actuator-plan.json")
}

pub(crate) fn desired_links_path(site_state_root: &Path) -> PathBuf {
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

pub(crate) fn parse_control_endpoint(raw: &str) -> Result<ControlEndpoint> {
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

pub(crate) fn decode_public_key(value: &str) -> Result<[u8; 32]> {
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
