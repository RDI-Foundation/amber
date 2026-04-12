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
        direct::{DirectPlan, DirectRuntimeUrlSource},
        vm::{VM_PLAN_FILENAME, VmPlan},
    },
    run_plan::{RunLink, RunPlan, RunSitePlan, SiteKind},
};
use amber_manifest::{CapabilityKind, CapabilityTransport, NetworkProtocol};
use amber_mesh::{
    InboundRoute, InboundTarget, MESH_CONFIG_FILENAME, MESH_IDENTITY_FILENAME, MeshConfig,
    MeshConfigPublic, MeshIdentity, MeshIdentityPublic, MeshIdentitySecret, MeshPeer, MeshProtocol,
    MeshProvisionOutput, MeshProvisionPlan, MeshProvisionTargetKind, OutboundRoute,
    TransportConfig, component_route_id, http_route_plugins_for_capability_kind,
    router_dynamic_export_route_id, router_export_route_id,
    telemetry::{SCENARIO_RUN_ID_ENV, SCENARIO_SCOPE_ENV},
};
use amber_proxy::{
    ControlEndpoint, RouterDiscovery, apply_route_overlay_with_retry, discover_router_for_output,
    fetch_router_identity, load_output_proxy_metadata, register_export_peer_with_retry,
    register_external_slot_with_retry, revoke_route_overlay_with_retry,
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
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
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
        DynamicInputRouteRecord, DynamicInputRouteTarget, DynamicProxyExportRecord,
        DynamicSitePlanRecord, SiteActuatorDestroyRequest, SiteActuatorPrepareRequest,
        SiteActuatorPublishRequest,
    },
    run_inputs::{collect_run_interface, validate_export_bindings, validate_slot_bindings},
    site_proxy_metadata::load_site_proxy_metadata,
    tcp_readiness::{
        endpoint_accepts_stable_connection, endpoint_returns_http_response, wait_for_http_response,
        wait_for_stable_endpoint,
    },
    vm_runtime::{
        TCG_VM_STARTUP_TIMEOUT, VmLaunchPreview, VmRuntimeState, VmSiteLaunchPreview,
        build_vm_site_launch_preview, ensure_control_socket_link, vm_current_control_socket_path,
        vm_endpoint_forward_ready_timeout, vm_uses_tcg_accel, write_vm_runtime_state,
    },
};
mod launch_bundle;
mod outside_proxy;
mod supervisor;

pub(crate) use self::{launch_bundle::*, outside_proxy::*, supervisor::*};

const RECEIPT_SCHEMA: &str = "amber.run.receipt";
const RECEIPT_VERSION: u32 = 3;
const LAUNCH_BUNDLE_SCHEMA: &str = "amber.run.launch_bundle";
const DYNAMIC_COMPOSE_CHILD_SCHEMA: &str = "amber.run.dynamic_compose_child";
const DYNAMIC_COMPOSE_CHILD_VERSION: u32 = 1;
const DYNAMIC_COMPOSE_MESH_ROOT: &str = ".amber/mesh";
const DYNAMIC_ROUTE_OVERLAY_FILENAME: &str = "site-router-overlay.json";
const DYNAMIC_PROXY_EXPORTS_FILENAME: &str = "proxy-exports.json";
const COMPOSE_PROVISIONER_SERVICE_NAME: &str = "amber-provisioner";
const COMPOSE_ROUTER_SERVICE_NAME: &str = "amber-router";
const KUBERNETES_MESH_PROVISION_CONFIGMAP_PATH: &str = "01-configmaps/amber-mesh-provision.yaml";
const KUBERNETES_PROVISIONER_JOB_PATH: &str = "02-rbac/amber-provisioner-job.yaml";
const KUBERNETES_PROVISIONER_ROLE_PATH: &str = "02-rbac/amber-provisioner-role.yaml";
const KUBERNETES_PROVISIONER_ROLEBINDING_PATH: &str = "02-rbac/amber-provisioner-rolebinding.yaml";
const KUBERNETES_PROVISIONER_SERVICE_ACCOUNT_PATH: &str = "02-rbac/amber-provisioner-sa.yaml";
const KUBERNETES_ROUTER_EXTERNAL_SECRET_NAME: &str = "amber-router-external";
const KUBERNETES_ROUTER_COMPONENT_NAME: &str = "amber-router";
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
    pub(crate) mesh_scope: String,
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

#[derive(Clone, Debug)]
pub(crate) struct LiveComponentRuntimeMetadata {
    pub(crate) moniker: String,
    pub(crate) host_mesh_addr: String,
    pub(crate) mesh_config: MeshConfigPublic,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SiteActuatorChildRecord {
    child_id: u64,
    artifact_root: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    assigned_components: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    proxy_exports: BTreeMap<String, DynamicProxyExportRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    routed_inputs: Vec<DynamicInputRouteRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    process_pid: Option<u32>,
    published: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DynamicComposeChildMetadata {
    schema: String,
    version: u32,
    services: Vec<String>,
    readiness_services: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredRouteOverlayPayload {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    peers: Vec<MeshPeer>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    inbound_routes: Vec<InboundRoute>,
}

#[derive(Debug, Deserialize)]
struct KubernetesSecretPayload {
    #[serde(default)]
    data: BTreeMap<String, String>,
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
    router_auth_token: String,
    control_state_auth_token: String,
    dynamic_caps_token_verify_key_b64: String,
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
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) external_slot_overlays: BTreeMap<String, DesiredExternalSlotOverlay>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) export_peer_overlays: BTreeMap<String, DesiredExportPeerOverlay>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DesiredExportPeer {
    pub(crate) export_name: String,
    pub(crate) peer_id: String,
    pub(crate) peer_key_b64: String,
    pub(crate) protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) route_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DesiredExternalSlotOverlay {
    pub(crate) slot_name: String,
    pub(crate) url: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DesiredExportPeerOverlay {
    pub(crate) export_name: String,
    pub(crate) peer_id: String,
    pub(crate) peer_key_b64: String,
    pub(crate) protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) route_id: Option<String>,
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
    component: String,
    provide: String,
    capability_kind: Option<String>,
    capability_profile: Option<String>,
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

pub(crate) async fn stop_bridge_proxies(
    bridge_proxies: &mut BTreeMap<BridgeProxyKey, BridgeProxyHandle>,
) -> Result<()> {
    for bridge in bridge_proxies.values_mut() {
        supervisor::stop_child(&mut bridge.child).await?;
    }
    bridge_proxies.clear();
    Ok(())
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
    if let Some(site_state_root) = state_path.parent() {
        cleanup_dynamic_site_children(site_state_root, site.kind)?;
    }
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

fn dynamic_compose_child_metadata_path(artifact_root: &Path) -> PathBuf {
    artifact_root.join(".amber").join("compose-child.json")
}

fn dynamic_route_overlay_path(artifact_root: &Path) -> PathBuf {
    artifact_root
        .join(".amber")
        .join(DYNAMIC_ROUTE_OVERLAY_FILENAME)
}

fn write_dynamic_route_overlay_payload(
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

fn write_dynamic_proxy_exports_metadata(
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

fn load_dynamic_proxy_exports_metadata(
    artifact_root: &Path,
) -> Result<BTreeMap<String, DynamicProxyExportRecord>> {
    let path = dynamic_proxy_exports_path(artifact_root);
    if !path.is_file() {
        return Ok(BTreeMap::new());
    }
    read_json(&path, "dynamic proxy exports")
}

pub(super) fn cleanup_dynamic_site_children(site_state_root: &Path, kind: SiteKind) -> Result<()> {
    let state_path = site_actuator_state_path(site_state_root);
    if !state_path.is_file() {
        return Ok(());
    }
    let mut state: SiteActuatorState = read_json(&state_path, "site actuator state")?;
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

fn cleanup_dynamic_compose_child(
    plan: &SiteSupervisorPlan,
    child: &SiteActuatorChildRecord,
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
                Ok((
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
                        (
                            serde_yaml::Value::String("route_id".to_string()),
                            serde_yaml::Value::String(dynamic_proxy_export_route_id(name, export)?),
                        ),
                    ])),
                ))
            })
            .collect::<Result<serde_yaml::Mapping>>()?;
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
                Ok((
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
                        (
                            "route_id".to_string(),
                            JsonValue::String(dynamic_proxy_export_route_id(name, export)?),
                        ),
                    ])),
                ))
            })
            .collect::<Result<JsonMap<_, _>>>()?;
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

fn yaml_string(value: &str) -> serde_yaml::Value {
    serde_yaml::Value::String(value.to_string())
}

fn compose_services<'a>(
    document: &'a serde_yaml::Value,
    path: &Path,
) -> Result<&'a serde_yaml::Mapping> {
    document
        .as_mapping()
        .and_then(|root| root.get(yaml_string("services")))
        .and_then(serde_yaml::Value::as_mapping)
        .ok_or_else(|| {
            miette::miette!(
                "compose file {} is missing a services mapping",
                path.display()
            )
        })
}

fn compose_services_mut<'a>(
    document: &'a mut serde_yaml::Value,
    path: &Path,
) -> Result<&'a mut serde_yaml::Mapping> {
    document
        .as_mapping_mut()
        .and_then(|root| root.get_mut(yaml_string("services")))
        .and_then(serde_yaml::Value::as_mapping_mut)
        .ok_or_else(|| {
            miette::miette!(
                "compose file {} is missing a services mapping",
                path.display()
            )
        })
}

fn compose_networks_mut<'a>(
    document: &'a mut serde_yaml::Value,
    path: &Path,
) -> Result<Option<&'a mut serde_yaml::Mapping>> {
    let Some(root) = document.as_mapping_mut() else {
        return Err(miette::miette!(
            "compose file {} is not a mapping",
            path.display()
        ));
    };
    Ok(root
        .get_mut(yaml_string("networks"))
        .and_then(serde_yaml::Value::as_mapping_mut))
}

fn assign_compose_egress_network_subnets(
    artifact_dir: &Path,
    run_id: &str,
    site_id: &str,
) -> Result<()> {
    let compose_path = artifact_dir.join("compose.yaml");
    if !compose_path.is_file() {
        return Ok(());
    }

    let mut document = read_compose_document(&compose_path)?;
    let Some(networks) = compose_networks_mut(&mut document, &compose_path)? else {
        return Ok(());
    };

    let mut used_subnets = networks
        .values()
        .filter_map(compose_network_subnet)
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    let mut changed = false;

    for (name, network) in networks.iter_mut() {
        let Some(name) = name.as_str() else {
            continue;
        };
        if !name.starts_with("amber_egress_") || compose_network_subnet(network).is_some() {
            continue;
        }
        let subnet = next_compose_egress_subnet(run_id, site_id, name, &used_subnets);
        set_compose_network_subnet(network, &subnet)?;
        used_subnets.insert(subnet);
        changed = true;
    }

    if !changed {
        return Ok(());
    }

    let rendered = serde_yaml::to_string(&document)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to serialize {}", compose_path.display()))?;
    fs::write(&compose_path, rendered)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", compose_path.display()))
}

fn compose_network_subnet(network: &serde_yaml::Value) -> Option<&str> {
    network
        .as_mapping()
        .and_then(|mapping| mapping.get(yaml_string("ipam")))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|ipam| ipam.get(yaml_string("config")))
        .and_then(serde_yaml::Value::as_sequence)
        .and_then(|configs| configs.first())
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|config| config.get(yaml_string("subnet")))
        .and_then(serde_yaml::Value::as_str)
}

fn set_compose_network_subnet(network: &mut serde_yaml::Value, subnet: &str) -> Result<()> {
    let Some(mapping) = network.as_mapping_mut() else {
        return Err(miette::miette!(
            "compose network definition is not a mapping"
        ));
    };
    mapping.insert(
        yaml_string("ipam"),
        serde_yaml::Value::Mapping(serde_yaml::Mapping::from_iter([(
            yaml_string("config"),
            serde_yaml::Value::Sequence(vec![serde_yaml::Value::Mapping(
                serde_yaml::Mapping::from_iter([(yaml_string("subnet"), yaml_string(subnet))]),
            )]),
        )])),
    );
    Ok(())
}

fn next_compose_egress_subnet(
    run_id: &str,
    site_id: &str,
    network_name: &str,
    used_subnets: &BTreeSet<String>,
) -> String {
    let digest = Sha256::digest(format!("{run_id}:{site_id}:{network_name}"));
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&digest[..4]);
    let base = u32::from_be_bytes(bytes) % COMPOSE_EGRESS_SUBNET_COUNT;
    for offset in 0..COMPOSE_EGRESS_SUBNET_COUNT {
        let candidate =
            compose_egress_subnet_from_index((base + offset) % COMPOSE_EGRESS_SUBNET_COUNT);
        if !used_subnets.contains(&candidate) {
            return candidate;
        }
    }
    unreachable!("compose egress subnet pool exhausted")
}

const COMPOSE_EGRESS_SUBNET_COUNT: u32 = 1 << 18;

fn compose_egress_subnet_from_index(index: u32) -> String {
    let second_octet = 64 + ((index >> 12) & 0x3f);
    let third_octet = (index >> 4) & 0xff;
    let fourth_octet = (index & 0x0f) << 4;
    format!("100.{second_octet}.{third_octet}.{fourth_octet}/28")
}

fn compose_service_names(document: &serde_yaml::Value, path: &Path) -> Result<BTreeSet<String>> {
    Ok(compose_services(document, path)?
        .keys()
        .filter_map(serde_yaml::Value::as_str)
        .map(str::to_string)
        .collect())
}

fn compose_service_dependency_names(service: &serde_yaml::Value) -> Result<Vec<String>> {
    let Some(mapping) = service.as_mapping() else {
        return Err(miette::miette!(
            "compose service definition is not a mapping"
        ));
    };
    let Some(depends_on) = mapping.get(yaml_string("depends_on")) else {
        return Ok(Vec::new());
    };
    if let Some(sequence) = depends_on.as_sequence() {
        return Ok(sequence
            .iter()
            .filter_map(serde_yaml::Value::as_str)
            .map(str::to_string)
            .collect());
    }
    if let Some(depends_on_map) = depends_on.as_mapping() {
        return Ok(depends_on_map
            .keys()
            .filter_map(serde_yaml::Value::as_str)
            .map(str::to_string)
            .collect());
    }
    Err(miette::miette!(
        "compose service has invalid depends_on declaration"
    ))
}

fn retain_compose_service_dependencies(
    service: &mut serde_yaml::Value,
    keep_services: &BTreeSet<String>,
) -> Result<()> {
    let Some(mapping) = service.as_mapping_mut() else {
        return Err(miette::miette!(
            "compose service definition is not a mapping"
        ));
    };
    let depends_on_key = yaml_string("depends_on");
    let Some(depends_on) = mapping.get_mut(&depends_on_key) else {
        return Ok(());
    };
    match depends_on {
        serde_yaml::Value::Sequence(sequence) => {
            sequence.retain(|value| {
                value
                    .as_str()
                    .is_some_and(|name| keep_services.contains(name))
            });
            if sequence.is_empty() {
                mapping.remove(&depends_on_key);
            }
        }
        serde_yaml::Value::Mapping(depends_on_map) => {
            depends_on_map.retain(|key, _| {
                key.as_str()
                    .is_some_and(|name| keep_services.contains(name))
            });
            if depends_on_map.is_empty() {
                mapping.remove(&depends_on_key);
            }
        }
        _ => {
            return Err(miette::miette!(
                "compose service has invalid depends_on declaration"
            ));
        }
    }
    Ok(())
}

fn compose_dynamic_root_service_names(
    artifact_root: &Path,
    assigned_components: &[String],
) -> Result<BTreeSet<String>> {
    let compose_path = artifact_root.join("compose.yaml");
    let document = read_compose_document(&compose_path)?;
    let service_names = compose_service_names(&document, &compose_path)?;
    let plan = read_embedded_compose_mesh_provision_plan(artifact_root)?;
    let assigned = assigned_components
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut out = BTreeSet::new();
    for target in plan.targets {
        if !matches!(target.kind, MeshProvisionTargetKind::Component)
            || !assigned.contains(target.config.identity.id.as_str())
        {
            continue;
        }
        let MeshProvisionOutput::Filesystem { dir } = target.output else {
            return Err(miette::miette!(
                "compose component {} does not use filesystem mesh output",
                target.config.identity.id
            ));
        };
        let sidecar = Path::new(&dir)
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
        if service_names.contains(&sidecar) {
            out.insert(sidecar.clone());
        }
        if let Some(program) = sidecar.strip_suffix("-net")
            && service_names.contains(program)
        {
            out.insert(program.to_string());
        }
    }
    if out.is_empty() {
        return Err(miette::miette!(
            "compose child artifact {} does not contain services for {:?}",
            compose_path.display(),
            assigned_components
        ));
    }
    Ok(out)
}

fn compose_live_service_names(
    plan: &SiteActuatorPlan,
    published_children: &[SiteActuatorChildRecord],
) -> Result<BTreeSet<String>> {
    let site_compose_path = Path::new(&plan.artifact_dir).join("compose.yaml");
    let site_document = read_compose_document(&site_compose_path)?;
    let mut live_services = compose_service_names(&site_document, &site_compose_path)?;
    for child in published_children {
        let child_compose_path = Path::new(&child.artifact_root).join("compose.yaml");
        let child_document = read_compose_document(&child_compose_path)?;
        live_services.extend(compose_service_names(&child_document, &child_compose_path)?);
    }
    Ok(live_services)
}

fn compose_service_closure(
    document: &serde_yaml::Value,
    compose_path: &Path,
    roots: &BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    let services = compose_services(document, compose_path)?;
    let mut closure = BTreeSet::new();
    let mut queue = roots.iter().cloned().collect::<Vec<_>>();
    while let Some(service_name) = queue.pop() {
        if !closure.insert(service_name.clone()) {
            continue;
        }
        let service = services.get(yaml_string(&service_name)).ok_or_else(|| {
            miette::miette!(
                "compose file {} is missing service {}",
                compose_path.display(),
                service_name
            )
        })?;
        for dependency in compose_service_dependency_names(service)? {
            queue.push(dependency);
        }
    }
    Ok(closure)
}

fn dynamic_compose_mesh_dir(service_name: &str) -> String {
    format!("{DYNAMIC_COMPOSE_MESH_ROOT}/{service_name}")
}

fn filter_dynamic_router_target(
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

fn dynamic_proxy_export_mesh_protocol(export: &DynamicProxyExportRecord) -> Result<MeshProtocol> {
    let protocol = export
        .protocol
        .parse::<NetworkProtocol>()
        .map_err(|err| miette::miette!("invalid dynamic proxy export protocol: {err}"))?;
    mesh_protocol(protocol)
}

fn dynamic_proxy_export_route_id(
    export_name: &str,
    export: &DynamicProxyExportRecord,
) -> Result<String> {
    Ok(router_dynamic_export_route_id(
        &export.component,
        export_name,
        dynamic_proxy_export_mesh_protocol(export)?,
    ))
}

fn dynamic_input_route_mesh_protocol(input: &DynamicInputRouteRecord) -> Result<MeshProtocol> {
    let protocol = input
        .protocol
        .parse::<NetworkProtocol>()
        .map_err(|err| miette::miette!("invalid dynamic routed-input protocol: {err}"))?;
    mesh_protocol(protocol)
}

fn dynamic_input_route_route_id(input: &DynamicInputRouteRecord, protocol: MeshProtocol) -> String {
    match &input.target {
        DynamicInputRouteTarget::ComponentProvide { provide } => {
            component_route_id(&input.provider_component, provide, protocol)
        }
    }
}

fn dynamic_input_route_capability(input: &DynamicInputRouteRecord) -> String {
    match &input.target {
        DynamicInputRouteTarget::ComponentProvide { provide } => provide.clone(),
    }
}

fn is_compose_component_sidecar_service(service_name: &str) -> bool {
    service_name.ends_with("-net")
}

fn overlay_peer_addr_map_from_ports(ports: &BTreeMap<String, u16>) -> BTreeMap<String, String> {
    ports
        .iter()
        .map(|(component, port)| (component.clone(), format!("127.0.0.1:{port}")))
        .collect()
}

fn overlay_issuer_sets(
    routed_inputs: &[DynamicInputRouteRecord],
) -> Result<BTreeMap<String, BTreeSet<String>>> {
    dynamic_route_issuer_grants(&[SiteActuatorChildRecord {
        child_id: 0,
        artifact_root: String::new(),
        assigned_components: Vec::new(),
        proxy_exports: BTreeMap::new(),
        routed_inputs: routed_inputs.to_vec(),
        process_pid: None,
        published: false,
    }])
}

fn overlay_upsert_peer(
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

fn overlay_upsert_route(routes: &mut Vec<InboundRoute>, route: InboundRoute) {
    if let Some(existing) = routes
        .iter_mut()
        .find(|existing| existing.route_id == route.route_id)
    {
        *existing = route;
    } else {
        routes.push(route);
    }
}

fn routed_input_overlay_route(
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
        http_plugins: http_route_plugins_for_capability_kind(
            Some(input.capability_kind.as_str()),
            protocol,
        ),
        target: InboundTarget::MeshForward {
            peer_addr: provider_peer_addr.to_string(),
            peer_id: input.provider_component.clone(),
            route_id: target_route_id,
            capability,
        },
        allowed_issuers,
    })
}

fn augment_route_overlay_payload(
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

fn routed_input_router_peer_addr(kind: SiteKind, router_mesh_port: Option<u16>) -> Result<String> {
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

fn router_mesh_port_from_plan(mesh_plan: &MeshProvisionPlan, artifact_kind: &str) -> Result<u16> {
    mesh_plan
        .targets
        .iter()
        .find(|target| matches!(target.kind, MeshProvisionTargetKind::Router))
        .map(|target| target.config.mesh_listen.port())
        .ok_or_else(|| {
            miette::miette!("{artifact_kind} mesh provision plan is missing its router mesh target")
        })
}

fn rewrite_dynamic_routed_inputs(
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
            route.http_plugins = http_route_plugins_for_capability_kind(
                Some(input.capability_kind.as_str()),
                protocol,
            );
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

fn rewrite_dynamic_routed_inputs_in_artifact(
    artifact_root: &Path,
    site_plan: &DynamicSitePlanRecord,
    router_mesh_port: Option<u16>,
) -> Result<()> {
    if site_plan.routed_inputs.is_empty() {
        return Ok(());
    }
    let path = artifact_root.join("mesh-provision-plan.json");
    let mut mesh_plan: MeshProvisionPlan = read_json(&path, "mesh provision plan")?;
    rewrite_dynamic_routed_inputs(
        &mut mesh_plan,
        &site_plan.routed_inputs,
        site_plan.kind,
        &site_plan.router_identity_id,
        router_mesh_port,
    )?;
    write_json(&path, &mesh_plan)
}

fn build_filesystem_route_overlay_base(
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

fn write_direct_vm_startup_route_overlay_payload(
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

fn write_direct_vm_live_route_overlay_payload(
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

fn ensure_dynamic_proxy_export_component_routes(
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
            http_plugins: http_route_plugins_for_capability_kind(
                Some(export.capability_kind.as_str()),
                protocol,
            ),
            target: InboundTarget::Local {
                port: export.target_port,
            },
            allowed_issuers: vec![router_identity_id.to_string()],
        });
    }
    Ok(())
}

fn ensure_dynamic_proxy_export_component_routes_in_artifact(
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

fn add_dynamic_proxy_export_overlay_routes(
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
            http_plugins: http_route_plugins_for_capability_kind(
                Some(export.capability_kind.as_str()),
                protocol,
            ),
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

struct DynamicComposeMeshPlan {
    mesh_plan: MeshProvisionPlan,
    mesh_dirs: BTreeMap<String, String>,
    component_mesh_dirs: BTreeMap<String, String>,
}

fn build_dynamic_compose_mesh_plan(
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
                let sidecar = Path::new(dir)
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
                *dir = relative_dir.clone();
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

fn compose_component_mesh_peer_addr(
    artifact_root: &Path,
    component_id: &str,
    output: &MeshProvisionOutput,
    mesh_port: u16,
) -> Result<String> {
    let MeshProvisionOutput::Filesystem { dir } = output else {
        return Err(miette::miette!(
            "compose artifact {} component {} does not use filesystem mesh output",
            artifact_root.display(),
            component_id
        ));
    };
    let service_name = Path::new(dir)
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            miette::miette!(
                "compose artifact {} component {} has invalid mesh output dir {}",
                artifact_root.display(),
                component_id,
                dir
            )
        })?;
    Ok(format!("{service_name}:{mesh_port}"))
}

fn kubernetes_component_mesh_peer_addr(
    artifact_root: &Path,
    component_id: &str,
    output: &MeshProvisionOutput,
    mesh_port: u16,
) -> Result<String> {
    let MeshProvisionOutput::KubernetesSecret { name, .. } = output else {
        return Err(miette::miette!(
            "kubernetes artifact {} component {} does not use a kubernetes secret mesh output",
            artifact_root.display(),
            component_id
        ));
    };
    let service_name = name.strip_suffix("-mesh").ok_or_else(|| {
        miette::miette!(
            "kubernetes artifact {} component {} uses invalid mesh secret name {}",
            artifact_root.display(),
            component_id,
            name
        )
    })?;
    Ok(format!("{service_name}:{mesh_port}"))
}

fn build_dynamic_compose_route_overlay_payload(
    artifact_root: &Path,
    assigned_components: &[String],
    component_mesh_dirs: &BTreeMap<String, String>,
    proxy_exports: &BTreeMap<String, DynamicProxyExportRecord>,
    routed_inputs: &[DynamicInputRouteRecord],
    existing_site_peer_identities: &BTreeMap<String, MeshIdentityPublic>,
) -> Result<StoredRouteOverlayPayload> {
    let plan = read_embedded_compose_mesh_provision_plan(artifact_root)?;
    let assigned = assigned_components
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let kept_component_ids = plan
        .targets
        .iter()
        .filter(|target| {
            matches!(target.kind, MeshProvisionTargetKind::Component)
                && assigned.contains(target.config.identity.id.as_str())
        })
        .map(|target| target.config.identity.id.clone())
        .collect::<BTreeSet<_>>();
    let mut router_target = plan
        .targets
        .iter()
        .find(|target| matches!(target.kind, MeshProvisionTargetKind::Router))
        .cloned()
        .ok_or_else(|| {
            miette::miette!(
                "compose child artifact {} is missing a router mesh target",
                artifact_root.join("compose.yaml").display()
            )
        })?;
    filter_dynamic_router_target(&mut router_target, &kept_component_ids);
    let component_peer_addrs = plan
        .targets
        .iter()
        .filter(|target| matches!(target.kind, MeshProvisionTargetKind::Component))
        .map(|target| {
            Ok((
                target.config.identity.id.clone(),
                compose_component_mesh_peer_addr(
                    artifact_root,
                    &target.config.identity.id,
                    &target.output,
                    target.config.mesh_listen.port(),
                )?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    for route in &mut router_target.config.inbound {
        if let InboundTarget::MeshForward {
            peer_id, peer_addr, ..
        } = &mut route.target
            && let Some(resolved) = component_peer_addrs.get(peer_id)
        {
            *peer_addr = resolved.clone();
        }
    }

    let component_mesh_scopes = plan
        .targets
        .iter()
        .filter(|target| matches!(target.kind, MeshProvisionTargetKind::Component))
        .map(|target| {
            (
                target.config.identity.id.clone(),
                target.config.identity.mesh_scope.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut peer_identities = existing_site_peer_identities.clone();
    for (component, relative_dir) in component_mesh_dirs {
        let identity: MeshIdentitySecret = read_json(
            &artifact_root
                .join(relative_dir)
                .join(MESH_IDENTITY_FILENAME),
            "mesh identity",
        )?;
        peer_identities.insert(
            component.clone(),
            MeshIdentityPublic {
                id: identity.id.clone(),
                public_key: identity.public_key().into_diagnostic()?,
                mesh_scope: component_mesh_scopes.get(component).cloned().flatten(),
            },
        );
    }
    let peers = router_target
        .config
        .peers
        .iter()
        .map(|peer| {
            let identity = peer_identities.get(&peer.id).ok_or_else(|| {
                miette::miette!(
                    "compose child router overlay peer {} is missing a live mesh identity",
                    peer.id
                )
            })?;
            Ok(MeshPeer {
                id: identity.id.clone(),
                public_key: identity.public_key,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let allowed_issuers = overlay_issuer_sets(routed_inputs)?;
    let mut payload = StoredRouteOverlayPayload {
        peers,
        inbound_routes: router_target.config.inbound,
    };
    augment_route_overlay_payload(
        &mut payload,
        proxy_exports,
        routed_inputs,
        &component_peer_addrs,
        &peer_identities,
        Some(&allowed_issuers),
        false,
    )?;
    Ok(payload)
}

fn rewrite_compose_mesh_bind_mounts(
    artifact_root: &Path,
    mesh_dirs: &BTreeMap<String, String>,
) -> Result<()> {
    let compose_path = artifact_root.join("compose.yaml");
    let mut document = read_compose_document(&compose_path)?;
    let services = compose_services_mut(&mut document, &compose_path)?;
    for (service_name, relative_dir) in mesh_dirs {
        let service = services.get_mut(yaml_string(service_name)).ok_or_else(|| {
            miette::miette!(
                "compose file {} is missing child sidecar service {}",
                compose_path.display(),
                service_name
            )
        })?;
        let Some(service_mapping) = service.as_mapping_mut() else {
            return Err(miette::miette!(
                "compose service {} is not a mapping",
                service_name
            ));
        };
        let volumes_key = yaml_string("volumes");
        let volumes = service_mapping
            .get_mut(&volumes_key)
            .and_then(serde_yaml::Value::as_sequence_mut)
            .ok_or_else(|| {
                miette::miette!(
                    "compose child sidecar {} is missing a volumes list",
                    service_name
                )
            })?;
        let expected_prefix = format!("{service_name}-mesh:/amber/mesh");
        let replacement = serde_yaml::Value::String(format!("./{relative_dir}:/amber/mesh:ro"));
        let mut replaced = false;
        for volume in volumes.iter_mut() {
            if volume
                .as_str()
                .is_some_and(|value| value.starts_with(&expected_prefix))
            {
                *volume = replacement.clone();
                replaced = true;
            }
        }
        if !replaced {
            volumes.push(replacement);
        }
    }
    let rendered = serde_yaml::to_string(&document)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to serialize {}", compose_path.display()))?;
    fs::write(&compose_path, rendered)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", compose_path.display()))
}

fn load_dynamic_compose_child_metadata(
    artifact_root: &Path,
) -> Result<DynamicComposeChildMetadata> {
    read_json(
        &dynamic_compose_child_metadata_path(artifact_root),
        "dynamic compose child metadata",
    )
}

fn load_running_site_router_identity(plan: &SiteActuatorPlan) -> Result<MeshIdentityPublic> {
    let state: SiteManagerState = read_json(
        &Path::new(&plan.site_state_root).join("manager-state.json"),
        "site manager state",
    )?;
    let router_identity_id = state.router_identity_id.ok_or_else(|| {
        miette::miette!(
            "site `{}` manager state is missing router identity id",
            plan.site_id
        )
    })?;
    let router_public_key_b64 = state.router_public_key_b64.ok_or_else(|| {
        miette::miette!(
            "site `{}` manager state is missing router public key",
            plan.site_id
        )
    })?;
    Ok(MeshIdentityPublic {
        id: router_identity_id,
        public_key: decode_public_key(&router_public_key_b64)?,
        mesh_scope: Some(plan.mesh_scope.clone()),
    })
}

fn filesystem_component_peer_identities_for_artifact(
    artifact_root: &Path,
    mesh_plan: &MeshProvisionPlan,
    artifact_kind: &str,
    compose_project: Option<&str>,
) -> Result<BTreeMap<String, MeshIdentityPublic>> {
    let mut peers = BTreeMap::new();
    for target in &mesh_plan.targets {
        if !matches!(target.kind, MeshProvisionTargetKind::Component) {
            continue;
        }
        let MeshProvisionOutput::Filesystem { dir } = &target.output else {
            return Err(miette::miette!(
                "{artifact_kind} artifact {} has non-filesystem mesh output for component {}",
                artifact_root.display(),
                target.config.identity.id
            ));
        };
        let config: MeshConfigPublic = if Path::new(dir).is_absolute() {
            let compose_project = compose_project.ok_or_else(|| {
                miette::miette!(
                    "{artifact_kind} artifact {} uses absolute mesh output {} without a compose \
                     project",
                    artifact_root.display(),
                    dir
                )
            })?;
            let service_name = Path::new(dir)
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(|| {
                    miette::miette!(
                        "{artifact_kind} artifact {} has invalid absolute mesh output {}",
                        artifact_root.display(),
                        dir
                    )
                })?;
            read_compose_volume_mesh_config(compose_project, service_name)?
        } else {
            read_json(
                &artifact_root.join(dir).join(MESH_CONFIG_FILENAME),
                "mesh config",
            )?
        };
        peers.insert(config.identity.id.clone(), config.identity);
    }
    Ok(peers)
}

fn read_compose_volume_mesh_config(
    compose_project: &str,
    service_name: &str,
) -> Result<MeshConfigPublic> {
    let volume_name = format!("{compose_project}_{service_name}-mesh");
    let output = Command::new("docker")
        .arg("run")
        .arg("--rm")
        .arg("-v")
        .arg(format!("{volume_name}:/amber/mesh:ro"))
        .arg("busybox:1.36.1")
        .arg("cat")
        .arg(format!("/amber/mesh/{MESH_CONFIG_FILENAME}"))
        .output()
        .into_diagnostic()
        .wrap_err_with(|| {
            format!("failed to read compose mesh config from docker volume {volume_name}")
        })?;
    if !output.status.success() {
        return Err(miette::miette!(
            "failed to read compose mesh config from docker volume \
             {volume_name}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ));
    }
    serde_json::from_slice(&output.stdout)
        .into_diagnostic()
        .wrap_err_with(|| format!("docker volume {volume_name} returned invalid mesh config json"))
}

fn compose_peer_identities_for_artifact(
    artifact_root: &Path,
    compose_project: Option<&str>,
) -> Result<BTreeMap<String, MeshIdentityPublic>> {
    let mesh_plan = if artifact_root.join("mesh-provision-plan.json").is_file() {
        read_json(
            &artifact_root.join("mesh-provision-plan.json"),
            "mesh provision plan",
        )?
    } else {
        read_embedded_compose_mesh_provision_plan(artifact_root)?
    };
    filesystem_component_peer_identities_for_artifact(
        artifact_root,
        &mesh_plan,
        "compose",
        compose_project,
    )
}

fn local_compose_peer_identities(
    plan: &SiteActuatorPlan,
    published_children: &[SiteActuatorChildRecord],
) -> Result<BTreeMap<String, MeshIdentityPublic>> {
    let mut peers = BTreeMap::new();
    let router = load_running_site_router_identity(plan)?;
    peers.insert(router.id.clone(), router);
    peers.extend(compose_peer_identities_for_artifact(
        Path::new(&plan.artifact_dir),
        plan.compose_project.as_deref(),
    )?);
    for child in published_children {
        peers.extend(compose_peer_identities_for_artifact(
            Path::new(&child.artifact_root),
            plan.compose_project.as_deref(),
        )?);
    }
    Ok(peers)
}

fn kubernetes_peer_identities_for_artifact(
    plan: &SiteActuatorPlan,
    artifact_root: &Path,
) -> Result<BTreeMap<String, MeshIdentityPublic>> {
    let mesh_plan = read_embedded_kubernetes_mesh_provision_plan(artifact_root)?;
    let mut peers = BTreeMap::new();
    for target in &mesh_plan.targets {
        if !matches!(target.kind, MeshProvisionTargetKind::Component) {
            continue;
        }
        let MeshProvisionOutput::KubernetesSecret { name, namespace } = &target.output else {
            return Err(miette::miette!(
                "kubernetes artifact {} has non-secret mesh output for component {}",
                artifact_root.display(),
                target.config.identity.id
            ));
        };
        let config = load_kubernetes_mesh_config_public(plan, name, namespace.as_deref())?;
        peers.insert(config.identity.id.clone(), config.identity);
    }
    Ok(peers)
}

fn local_kubernetes_peer_identities(
    plan: &SiteActuatorPlan,
    published_children: &[SiteActuatorChildRecord],
) -> Result<BTreeMap<String, MeshIdentityPublic>> {
    let mut peers = BTreeMap::new();
    let router = load_running_site_router_identity(plan)?;
    peers.insert(router.id.clone(), router);
    peers.extend(kubernetes_peer_identities_for_artifact(
        plan,
        Path::new(&plan.artifact_dir),
    )?);
    for child in published_children {
        peers.extend(kubernetes_peer_identities_for_artifact(
            plan,
            Path::new(&child.artifact_root),
        )?);
    }
    Ok(peers)
}

pub(crate) fn collect_live_component_runtime_metadata(
    plan: &SiteActuatorPlan,
) -> Result<BTreeMap<String, LiveComponentRuntimeMetadata>> {
    let state: SiteActuatorState = read_json(
        &site_actuator_state_path(Path::new(&plan.site_state_root)),
        "site actuator state",
    )?;
    let published_children = state
        .children
        .values()
        .filter(|child| child.published)
        .cloned()
        .collect::<Vec<_>>();
    let mut components = match plan.kind {
        SiteKind::Direct => collect_direct_artifact_runtime_metadata(
            Path::new(&plan.artifact_dir),
            Path::new(plan.runtime_root.as_deref().ok_or_else(|| {
                miette::miette!("direct site `{}` is missing its runtime root", plan.site_id)
            })?),
        )?,
        SiteKind::Vm => collect_vm_artifact_runtime_metadata(
            Path::new(&plan.artifact_dir),
            Path::new(plan.runtime_root.as_deref().ok_or_else(|| {
                miette::miette!("vm site `{}` is missing its runtime root", plan.site_id)
            })?),
        )?,
        SiteKind::Compose => collect_compose_artifact_runtime_metadata(
            Path::new(&plan.artifact_dir),
            plan.compose_project.as_deref(),
        )?,
        SiteKind::Kubernetes => {
            collect_kubernetes_artifact_runtime_metadata(plan, Path::new(&plan.artifact_dir))?
        }
    };
    for child in &published_children {
        let child_components = match plan.kind {
            SiteKind::Direct => collect_direct_artifact_runtime_metadata(
                Path::new(&child.artifact_root),
                &site_actuator_child_runtime_root(plan, child.child_id),
            )?,
            SiteKind::Vm => collect_vm_artifact_runtime_metadata(
                Path::new(&child.artifact_root),
                &site_actuator_child_runtime_root(plan, child.child_id),
            )?,
            SiteKind::Compose => collect_compose_artifact_runtime_metadata(
                Path::new(&child.artifact_root),
                plan.compose_project.as_deref(),
            )?,
            SiteKind::Kubernetes => {
                collect_kubernetes_artifact_runtime_metadata(plan, Path::new(&child.artifact_root))?
            }
        };
        components.extend(child_components);
    }
    Ok(components)
}

pub(crate) fn load_live_site_router_mesh_config(
    plan: &SiteActuatorPlan,
) -> Result<MeshConfigPublic> {
    let artifact_root = Path::new(&plan.artifact_dir);
    match plan.kind {
        SiteKind::Direct => {
            let runtime_root = Path::new(plan.runtime_root.as_deref().ok_or_else(|| {
                miette::miette!("direct site `{}` is missing its runtime root", plan.site_id)
            })?);
            let direct_plan: DirectPlan =
                read_json(&artifact_root.join("direct-plan.json"), "direct plan")?;
            let router = direct_plan.router.ok_or_else(|| {
                miette::miette!("direct site `{}` is missing its router plan", plan.site_id)
            })?;
            read_json(&runtime_root.join(&router.mesh_config_path), "mesh config")
        }
        SiteKind::Vm => {
            let runtime_root = Path::new(plan.runtime_root.as_deref().ok_or_else(|| {
                miette::miette!("vm site `{}` is missing its runtime root", plan.site_id)
            })?);
            let vm_plan: VmPlan = read_json(&artifact_root.join("vm-plan.json"), "vm plan")?;
            let router = vm_plan.router.ok_or_else(|| {
                miette::miette!("vm site `{}` is missing its router plan", plan.site_id)
            })?;
            read_json(&runtime_root.join(&router.mesh_config_path), "mesh config")
        }
        SiteKind::Compose => {
            let mesh_plan = if artifact_root.join("mesh-provision-plan.json").is_file() {
                read_json(
                    &artifact_root.join("mesh-provision-plan.json"),
                    "mesh provision plan",
                )?
            } else {
                read_embedded_compose_mesh_provision_plan(artifact_root)?
            };
            let target = mesh_plan
                .targets
                .iter()
                .find(|target| matches!(target.kind, MeshProvisionTargetKind::Router))
                .ok_or_else(|| {
                    miette::miette!(
                        "compose site `{}` is missing a router mesh target",
                        plan.site_id
                    )
                })?;
            let MeshProvisionOutput::Filesystem { dir } = &target.output else {
                return Err(miette::miette!(
                    "compose site `{}` has non-filesystem mesh output for router {}",
                    plan.site_id,
                    target.config.identity.id
                ));
            };
            if Path::new(dir).is_absolute() {
                let compose_project = plan.compose_project.as_deref().ok_or_else(|| {
                    miette::miette!(
                        "compose site `{}` is missing its compose project",
                        plan.site_id
                    )
                })?;
                let service_name = Path::new(dir)
                    .file_name()
                    .and_then(|value| value.to_str())
                    .ok_or_else(|| {
                        miette::miette!(
                            "compose site `{}` has invalid router mesh output {}",
                            plan.site_id,
                            dir
                        )
                    })?;
                read_compose_volume_mesh_config(compose_project, service_name)
            } else {
                read_json(
                    &artifact_root.join(dir).join(MESH_CONFIG_FILENAME),
                    "mesh config",
                )
            }
        }
        SiteKind::Kubernetes => {
            let mesh_plan = read_kubernetes_runtime_mesh_provision_plan(artifact_root)?;
            let target = mesh_plan
                .targets
                .iter()
                .find(|target| matches!(target.kind, MeshProvisionTargetKind::Router))
                .ok_or_else(|| {
                    miette::miette!(
                        "kubernetes site `{}` is missing a router mesh target",
                        plan.site_id
                    )
                })?;
            let MeshProvisionOutput::KubernetesSecret { name, namespace } = &target.output else {
                return Err(miette::miette!(
                    "kubernetes site `{}` has non-secret mesh output for router {}",
                    plan.site_id,
                    target.config.identity.id
                ));
            };
            load_kubernetes_mesh_config_public(plan, name, namespace.as_deref())
        }
    }
}

fn collect_direct_artifact_runtime_metadata(
    artifact_root: &Path,
    runtime_root: &Path,
) -> Result<BTreeMap<String, LiveComponentRuntimeMetadata>> {
    let state: crate::direct_runtime::DirectRuntimeState = read_json(
        &direct_runtime_state_path(artifact_root),
        "direct runtime state",
    )?;
    let plan: DirectPlan = read_json(&artifact_root.join("direct-plan.json"), "direct plan")?;
    let mut components = BTreeMap::new();
    for component in &plan.components {
        let mesh_config: MeshConfigPublic = read_json(
            &runtime_root.join(&component.sidecar.mesh_config_path),
            "mesh config",
        )?;
        let mesh_port = state
            .component_mesh_port_by_id
            .get(&component.id)
            .copied()
            .ok_or_else(|| {
                miette::miette!(
                    "direct runtime state is missing mesh port for component {}",
                    component.moniker
                )
            })?;
        components.insert(
            component.moniker.clone(),
            LiveComponentRuntimeMetadata {
                moniker: component.moniker.clone(),
                host_mesh_addr: format!("127.0.0.1:{mesh_port}"),
                mesh_config,
            },
        );
    }
    Ok(components)
}

fn collect_vm_artifact_runtime_metadata(
    artifact_root: &Path,
    runtime_root: &Path,
) -> Result<BTreeMap<String, LiveComponentRuntimeMetadata>> {
    let state = load_vm_runtime_state_for_artifact(artifact_root, runtime_root)?;
    let plan: VmPlan = read_json(&artifact_root.join("vm-plan.json"), "vm plan")?;
    let mut components = BTreeMap::new();
    for component in &plan.components {
        let mesh_config: MeshConfigPublic = read_json(
            &runtime_root.join(&component.mesh_config_path),
            "mesh config",
        )?;
        let mesh_port = state
            .component_mesh_port_by_id
            .get(&component.id)
            .copied()
            .ok_or_else(|| {
                miette::miette!(
                    "vm runtime state is missing mesh port for component {}",
                    component.moniker
                )
            })?;
        components.insert(
            component.moniker.clone(),
            LiveComponentRuntimeMetadata {
                moniker: component.moniker.clone(),
                host_mesh_addr: format!("127.0.0.1:{mesh_port}"),
                mesh_config,
            },
        );
    }
    Ok(components)
}

fn collect_compose_artifact_runtime_metadata(
    artifact_root: &Path,
    compose_project: Option<&str>,
) -> Result<BTreeMap<String, LiveComponentRuntimeMetadata>> {
    let mesh_plan = if artifact_root.join("mesh-provision-plan.json").is_file() {
        read_json(
            &artifact_root.join("mesh-provision-plan.json"),
            "mesh provision plan",
        )?
    } else {
        read_embedded_compose_mesh_provision_plan(artifact_root)?
    };
    let mut components = BTreeMap::new();
    for target in &mesh_plan.targets {
        if !matches!(target.kind, MeshProvisionTargetKind::Component) {
            continue;
        }
        let MeshProvisionOutput::Filesystem { dir } = &target.output else {
            return Err(miette::miette!(
                "compose artifact {} has non-filesystem mesh output for component {}",
                artifact_root.display(),
                target.config.identity.id
            ));
        };
        let service_name = Path::new(dir)
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| {
                miette::miette!(
                    "compose artifact {} has invalid mesh output {} for component {}",
                    artifact_root.display(),
                    dir,
                    target.config.identity.id
                )
            })?;
        let mesh_config = if Path::new(dir).is_absolute() {
            let compose_project = compose_project.ok_or_else(|| {
                miette::miette!(
                    "compose artifact {} requires a compose project to resolve mesh output {}",
                    artifact_root.display(),
                    dir
                )
            })?;
            read_compose_volume_mesh_config(compose_project, service_name)?
        } else {
            read_json(
                &artifact_root.join(dir).join(MESH_CONFIG_FILENAME),
                "mesh config",
            )?
        };
        components.insert(
            target.config.identity.id.clone(),
            LiveComponentRuntimeMetadata {
                moniker: target.config.identity.id.clone(),
                host_mesh_addr: compose_component_mesh_peer_addr(
                    artifact_root,
                    &target.config.identity.id,
                    &target.output,
                    mesh_config.mesh_listen.port(),
                )?,
                mesh_config,
            },
        );
    }
    Ok(components)
}

fn collect_kubernetes_artifact_runtime_metadata(
    plan: &SiteActuatorPlan,
    artifact_root: &Path,
) -> Result<BTreeMap<String, LiveComponentRuntimeMetadata>> {
    let mesh_plan = read_kubernetes_runtime_mesh_provision_plan(artifact_root)?;
    let mut components = BTreeMap::new();
    for target in &mesh_plan.targets {
        if !matches!(target.kind, MeshProvisionTargetKind::Component) {
            continue;
        }
        let MeshProvisionOutput::KubernetesSecret { name, namespace } = &target.output else {
            return Err(miette::miette!(
                "kubernetes artifact {} has non-secret mesh output for component {}",
                artifact_root.display(),
                target.config.identity.id
            ));
        };
        name.strip_suffix("-mesh").ok_or_else(|| {
            miette::miette!(
                "kubernetes artifact {} component {} uses invalid mesh secret name {}",
                artifact_root.display(),
                target.config.identity.id,
                name
            )
        })?;
        let mesh_config = load_kubernetes_mesh_config_public(plan, name, namespace.as_deref())?;
        components.insert(
            target.config.identity.id.clone(),
            LiveComponentRuntimeMetadata {
                moniker: target.config.identity.id.clone(),
                host_mesh_addr: kubernetes_component_mesh_peer_addr(
                    artifact_root,
                    &target.config.identity.id,
                    &target.output,
                    mesh_config.mesh_listen.port(),
                )?,
                mesh_config,
            },
        );
    }
    Ok(components)
}

fn prepare_dynamic_compose_child_artifact(
    plan: &SiteActuatorPlan,
    site_plan: &DynamicSitePlanRecord,
    artifact_root: &Path,
    published_children: &[SiteActuatorChildRecord],
    existing_site_peer_identities: &BTreeMap<String, MeshIdentityPublic>,
) -> Result<()> {
    project_dynamic_child_mesh_scope(artifact_root, Some(&plan.mesh_scope))?;
    let compose_path = artifact_root.join("compose.yaml");
    let mut desired_document = read_compose_document(&compose_path)?;
    let root_services =
        compose_dynamic_root_service_names(artifact_root, &site_plan.assigned_components)?;
    let service_closure =
        compose_service_closure(&desired_document, &compose_path, &root_services)?;
    let live_services = compose_live_service_names(plan, published_children)?;
    let mut kept_services = service_closure
        .difference(&live_services)
        .cloned()
        .collect::<BTreeSet<_>>();
    kept_services.remove(COMPOSE_PROVISIONER_SERVICE_NAME);
    if kept_services.is_empty() {
        return Err(miette::miette!(
            "compose child artifact {} does not retain any child-owned services after filtering",
            compose_path.display()
        ));
    }

    let services = compose_services_mut(&mut desired_document, &compose_path)?;
    services.retain(|name, _| {
        name.as_str()
            .is_some_and(|service_name| kept_services.contains(service_name))
    });
    for service in services.values_mut() {
        retain_compose_service_dependencies(service, &kept_services)?;
    }
    let rendered = serde_yaml::to_string(&desired_document)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to serialize {}", compose_path.display()))?;
    fs::write(&compose_path, rendered)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", compose_path.display()))?;

    let DynamicComposeMeshPlan {
        mesh_plan,
        mesh_dirs,
        component_mesh_dirs,
    } = build_dynamic_compose_mesh_plan(artifact_root, &site_plan.assigned_components)?;
    let mut mesh_plan = mesh_plan;
    let router_mesh_port = router_mesh_port_from_plan(
        &read_embedded_compose_mesh_provision_plan(artifact_root)?,
        "compose",
    )?;
    ensure_dynamic_proxy_export_component_routes(
        &mut mesh_plan,
        &site_plan.proxy_exports,
        &plan.router_identity_id,
    )?;
    rewrite_dynamic_routed_inputs(
        &mut mesh_plan,
        &site_plan.routed_inputs,
        SiteKind::Compose,
        &plan.router_identity_id,
        Some(router_mesh_port),
    )?;
    let existing_peer_identities = crate::direct_runtime::required_existing_mesh_peer_identities(
        &mesh_plan,
        existing_site_peer_identities,
    )?;
    mesh_plan.existing_peer_identities = existing_peer_identities.values().cloned().collect();
    write_json(&artifact_root.join("mesh-provision-plan.json"), &mesh_plan)?;
    crate::direct_runtime::provision_mesh_filesystem_with_peer_identities(
        &mesh_plan,
        artifact_root,
        &existing_peer_identities,
    )?;
    for relative_dir in mesh_dirs.values() {
        crate::direct_runtime::project_existing_peer_identities_into_mesh_config(
            &artifact_root.join(relative_dir).join(MESH_CONFIG_FILENAME),
            &existing_peer_identities,
        )?;
    }
    rewrite_compose_mesh_bind_mounts(artifact_root, &mesh_dirs)?;
    let overlay_payload = build_dynamic_compose_route_overlay_payload(
        artifact_root,
        &site_plan.assigned_components,
        &component_mesh_dirs,
        &site_plan.proxy_exports,
        &site_plan.routed_inputs,
        existing_site_peer_identities,
    )?;
    write_json(&dynamic_route_overlay_path(artifact_root), &overlay_payload)?;
    write_embedded_compose_mesh_provision_plan(artifact_root, &mesh_plan)?;

    write_json(
        &dynamic_compose_child_metadata_path(artifact_root),
        &DynamicComposeChildMetadata {
            schema: DYNAMIC_COMPOSE_CHILD_SCHEMA.to_string(),
            version: DYNAMIC_COMPOSE_CHILD_VERSION,
            services: kept_services.iter().cloned().collect(),
            readiness_services: root_services
                .into_iter()
                .filter(|service| kept_services.contains(service))
                .collect(),
        },
    )
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
    let plan_json = serde_json::to_string_pretty(plan)
        .into_diagnostic()
        .wrap_err("failed to serialize compose mesh provision plan")?;
    document
        .as_mapping_mut()
        .and_then(|root| root.get_mut(yaml_string("configs")))
        .and_then(serde_yaml::Value::as_mapping_mut)
        .and_then(|configs| configs.get_mut(yaml_string("amber-mesh-provision-plan")))
        .and_then(serde_yaml::Value::as_mapping_mut)
        .ok_or_else(|| {
            miette::miette!(
                "compose file {} is missing configs.amber-mesh-provision-plan",
                path.display()
            )
        })?
        .insert(yaml_string("content"), serde_yaml::Value::String(plan_json));
    let rendered = serde_yaml::to_string(&document)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to serialize {}", path.display()))?;
    fs::write(&path, rendered)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", path.display()))
}

fn read_embedded_kubernetes_mesh_provision_plan(artifact_root: &Path) -> Result<MeshProvisionPlan> {
    let path = artifact_root
        .join("01-configmaps")
        .join("amber-mesh-provision.yaml");
    let raw = fs::read_to_string(&path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", path.display()))?;
    let document: serde_yaml::Value =
        serde_yaml::from_str(&raw)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "invalid kubernetes mesh provision configmap {}",
                    path.display()
                )
            })?;
    let mesh_plan = document
        .as_mapping()
        .and_then(|root| root.get(yaml_string("data")))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|data| data.get(yaml_string("mesh-plan.json")))
        .and_then(serde_yaml::Value::as_str)
        .ok_or_else(|| {
            miette::miette!(
                "kubernetes mesh provision configmap {} is missing data.mesh-plan.json",
                path.display()
            )
        })?;
    serde_json::from_str(mesh_plan).map_err(|err| {
        miette::miette!(
            "kubernetes mesh provision configmap {} has invalid mesh plan: {err}",
            path.display()
        )
    })
}

fn read_kubernetes_runtime_mesh_provision_plan(artifact_root: &Path) -> Result<MeshProvisionPlan> {
    let path = artifact_root.join("mesh-provision-plan.json");
    if path.is_file() {
        return read_json(&path, "mesh provision plan");
    }
    read_embedded_kubernetes_mesh_provision_plan(artifact_root)
}

fn write_embedded_kubernetes_mesh_provision_plan(
    artifact_root: &Path,
    plan: &MeshProvisionPlan,
) -> Result<()> {
    let path = artifact_root.join(KUBERNETES_MESH_PROVISION_CONFIGMAP_PATH);
    let raw = fs::read_to_string(&path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", path.display()))?;
    let mut document: serde_yaml::Value = serde_yaml::from_str(&raw)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "invalid kubernetes mesh provision configmap {}",
                path.display()
            )
        })?;
    let plan_json = serde_json::to_string_pretty(plan)
        .into_diagnostic()
        .wrap_err("failed to serialize kubernetes mesh provision plan")?;
    document
        .as_mapping_mut()
        .and_then(|root| root.get_mut(yaml_string("data")))
        .and_then(serde_yaml::Value::as_mapping_mut)
        .ok_or_else(|| {
            miette::miette!(
                "kubernetes mesh provision configmap {} is missing a data mapping",
                path.display()
            )
        })?
        .insert(
            yaml_string("mesh-plan.json"),
            serde_yaml::Value::String(plan_json),
        );
    let rendered = serde_yaml::to_string(&document)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to serialize {}", path.display()))?;
    fs::write(&path, rendered)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", path.display()))
}

fn kubernetes_resource_name(document: &serde_yaml::Value) -> Option<&str> {
    document
        .as_mapping()
        .and_then(|root| root.get(yaml_string("metadata")))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|metadata| metadata.get(yaml_string("name")))
        .and_then(serde_yaml::Value::as_str)
}

fn kubernetes_dynamic_apply_resource_kept_from_contents(
    resource: &str,
    raw: &str,
    child_component_labels: &BTreeSet<String>,
) -> Result<bool> {
    if matches!(
        resource,
        KUBERNETES_MESH_PROVISION_CONFIGMAP_PATH
            | KUBERNETES_PROVISIONER_JOB_PATH
            | KUBERNETES_PROVISIONER_ROLE_PATH
            | KUBERNETES_PROVISIONER_ROLEBINDING_PATH
            | KUBERNETES_PROVISIONER_SERVICE_ACCOUNT_PATH
    ) || resource.starts_with("03-persistentvolumeclaims/")
    {
        return Ok(true);
    }

    let document: serde_yaml::Value = serde_yaml::from_str(raw)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid kubernetes resource {resource}"))?;
    Ok(document
        .as_mapping()
        .and_then(|root| root.get(yaml_string("metadata")))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|metadata| metadata.get(yaml_string("labels")))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|labels| labels.get(yaml_string("amber.io/component-id")))
        .and_then(serde_yaml::Value::as_str)
        .is_some_and(|component_id| child_component_labels.contains(component_id)))
}

pub(crate) fn project_kubernetes_dynamic_child_artifact_files(
    artifact_files: &BTreeMap<String, String>,
    component_ids: &[usize],
) -> Result<BTreeMap<String, String>> {
    let child_component_labels = component_ids
        .iter()
        .map(|component_id| format!("c{component_id}"))
        .collect::<BTreeSet<_>>();
    let kustomization_path = "kustomization.yaml";
    let raw = artifact_files.get(kustomization_path).ok_or_else(|| {
        miette::miette!("dynamic kubernetes artifact snapshot is missing {kustomization_path}")
    })?;
    let mut document: serde_yaml::Value = serde_yaml::from_str(raw)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid kustomization {kustomization_path}"))?;
    let root = document.as_mapping_mut().ok_or_else(|| {
        miette::miette!("kustomization {kustomization_path} is not a YAML mapping")
    })?;
    let resources = root
        .get_mut(yaml_string("resources"))
        .and_then(serde_yaml::Value::as_sequence_mut)
        .ok_or_else(|| {
            miette::miette!("kustomization {kustomization_path} is missing a resources sequence")
        })?;
    let mut projected = artifact_files
        .iter()
        .filter(|(path, _)| !path.ends_with(".yaml") && path.as_str() != kustomization_path)
        .map(|(path, contents)| (path.clone(), contents.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut kept_resources = Vec::new();
    let mut kept_resource_names = BTreeSet::new();
    for resource in resources
        .iter()
        .filter_map(serde_yaml::Value::as_str)
        .map(str::to_owned)
    {
        let raw = artifact_files
            .get(&resource)
            .ok_or_else(|| miette::miette!("dynamic kubernetes artifact is missing {resource}"))?;
        if !kubernetes_dynamic_apply_resource_kept_from_contents(
            &resource,
            raw,
            &child_component_labels,
        )? {
            continue;
        }
        let document: serde_yaml::Value = serde_yaml::from_str(raw)
            .into_diagnostic()
            .wrap_err_with(|| format!("invalid kubernetes resource {resource}"))?;
        if let Some(name) = kubernetes_resource_name(&document) {
            kept_resource_names.insert(name.to_string());
        }
        projected.insert(resource.clone(), raw.clone());
        kept_resources.push(serde_yaml::Value::String(resource));
    }
    *resources = kept_resources;

    if let Some(generators) = root
        .get_mut(yaml_string("secretGenerator"))
        .and_then(serde_yaml::Value::as_sequence_mut)
    {
        generators.retain(|generator| {
            generator
                .as_mapping()
                .and_then(|mapping| mapping.get(yaml_string("name")))
                .and_then(serde_yaml::Value::as_str)
                != Some(KUBERNETES_ROUTER_EXTERNAL_SECRET_NAME)
        });
    }

    if let Some(replacements) = root
        .get_mut(yaml_string("replacements"))
        .and_then(serde_yaml::Value::as_sequence_mut)
    {
        replacements.retain_mut(|replacement| {
            let Some(targets) = replacement
                .as_mapping_mut()
                .and_then(|mapping| mapping.get_mut(yaml_string("targets")))
                .and_then(serde_yaml::Value::as_sequence_mut)
            else {
                return false;
            };
            targets.retain(|target| {
                target
                    .as_mapping()
                    .and_then(|mapping| mapping.get(yaml_string("select")))
                    .and_then(serde_yaml::Value::as_mapping)
                    .and_then(|select| select.get(yaml_string("name")))
                    .and_then(serde_yaml::Value::as_str)
                    .is_some_and(|name| kept_resource_names.contains(name))
            });
            !targets.is_empty()
        });
    }

    let rendered = serde_yaml::to_string(&document)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to serialize {kustomization_path}"))?;
    projected.insert(kustomization_path.to_string(), rendered);
    Ok(projected)
}

fn project_kubernetes_dynamic_child_destroy_artifact_files(
    artifact_files: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    let kustomization_path = "kustomization.yaml";
    let raw = artifact_files.get(kustomization_path).ok_or_else(|| {
        miette::miette!("dynamic kubernetes artifact snapshot is missing {kustomization_path}")
    })?;
    let mut document: serde_yaml::Value = serde_yaml::from_str(raw)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid kustomization {kustomization_path}"))?;
    let root = document.as_mapping_mut().ok_or_else(|| {
        miette::miette!("kustomization {kustomization_path} is not a YAML mapping")
    })?;
    let resources = root
        .get_mut(yaml_string("resources"))
        .and_then(serde_yaml::Value::as_sequence_mut)
        .ok_or_else(|| {
            miette::miette!("kustomization {kustomization_path} is missing a resources sequence")
        })?;
    let mut projected = artifact_files
        .iter()
        .filter(|(path, _)| !path.ends_with(".yaml") && path.as_str() != kustomization_path)
        .map(|(path, contents)| (path.clone(), contents.clone()))
        .collect::<BTreeMap<_, _>>();
    let shared_paths = [
        KUBERNETES_MESH_PROVISION_CONFIGMAP_PATH,
        KUBERNETES_PROVISIONER_ROLE_PATH,
        KUBERNETES_PROVISIONER_ROLEBINDING_PATH,
        KUBERNETES_PROVISIONER_SERVICE_ACCOUNT_PATH,
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let mut kept_resources = Vec::new();
    for resource in resources
        .iter()
        .filter_map(serde_yaml::Value::as_str)
        .map(str::to_owned)
    {
        if shared_paths.contains(resource.as_str()) {
            continue;
        }
        let raw = artifact_files
            .get(&resource)
            .ok_or_else(|| miette::miette!("dynamic kubernetes artifact is missing {resource}"))?;
        projected.insert(resource.clone(), raw.clone());
        kept_resources.push(serde_yaml::Value::String(resource));
    }
    *resources = kept_resources;

    if let Some(generators) = root
        .get_mut(yaml_string("secretGenerator"))
        .and_then(serde_yaml::Value::as_sequence_mut)
    {
        generators.retain(|generator| {
            generator
                .as_mapping()
                .and_then(|mapping| mapping.get(yaml_string("name")))
                .and_then(serde_yaml::Value::as_str)
                != Some(KUBERNETES_ROUTER_EXTERNAL_SECRET_NAME)
        });
    }

    if let Some(replacements) = root
        .get_mut(yaml_string("replacements"))
        .and_then(serde_yaml::Value::as_sequence_mut)
    {
        replacements.clear();
    }

    let rendered = serde_yaml::to_string(&document)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to serialize {kustomization_path}"))?;
    projected.insert(kustomization_path.to_string(), rendered);
    Ok(projected)
}

fn read_artifact_snapshot(root: &Path) -> Result<BTreeMap<String, String>> {
    walk_files(root)?
        .into_iter()
        .map(|path| {
            let relative = path
                .strip_prefix(root)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to relativize {}", path.display()))?;
            let relative = path_to_forward_slash_string(relative);
            let contents = fs::read_to_string(&path)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to read {}", path.display()))?;
            Ok((relative, contents))
        })
        .collect()
}

fn rewrite_dynamic_kubernetes_apply_bundle(
    artifact_root: &Path,
    component_ids: &[usize],
) -> Result<()> {
    let files = read_artifact_snapshot(artifact_root)?;
    let projected = project_kubernetes_dynamic_child_artifact_files(&files, component_ids)?;
    replace_artifact_snapshot(artifact_root, &projected)
}

fn prepare_dynamic_kubernetes_child_artifact(
    plan: &SiteActuatorPlan,
    site_plan: &DynamicSitePlanRecord,
    artifact_root: &Path,
    existing_site_peer_identities: &BTreeMap<String, MeshIdentityPublic>,
) -> Result<()> {
    project_dynamic_child_mesh_scope(artifact_root, Some(&plan.mesh_scope))?;
    let plan_path = artifact_root.join("mesh-provision-plan.json");
    let mesh_plan = read_embedded_kubernetes_mesh_provision_plan(artifact_root)?;
    let router_mesh_port = router_mesh_port_from_plan(&mesh_plan, "kubernetes")?;
    let assigned = site_plan
        .assigned_components
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut kept_component_ids = BTreeSet::new();
    let mut router_target = None;
    let mut overlay_targets = Vec::with_capacity(mesh_plan.targets.len());
    let mut provision_targets = Vec::new();
    for target in mesh_plan.targets {
        match target.kind {
            MeshProvisionTargetKind::Component => {
                if assigned.contains(target.config.identity.id.as_str()) {
                    kept_component_ids.insert(target.config.identity.id.clone());
                    provision_targets.push(target.clone());
                    overlay_targets.push(target);
                }
            }
            MeshProvisionTargetKind::Router => {
                router_target = Some(target);
            }
        }
    }

    let Some(mut router_target) = router_target else {
        return Err(miette::miette!(
            "dynamic mesh provision plan {} is missing a router target",
            plan_path.display()
        ));
    };
    filter_dynamic_router_target(&mut router_target, &kept_component_ids);
    overlay_targets.push(router_target);
    let mut overlay_plan = MeshProvisionPlan {
        version: mesh_plan.version.clone(),
        identity_seed: mesh_plan.identity_seed.clone(),
        existing_peer_identities: Vec::new(),
        targets: overlay_targets,
    };
    let overlay_existing_peer_identities =
        crate::direct_runtime::required_existing_mesh_peer_identities(
            &overlay_plan,
            existing_site_peer_identities,
        )?;
    overlay_plan.existing_peer_identities =
        overlay_existing_peer_identities.values().cloned().collect();
    write_json(&plan_path, &overlay_plan)?;
    let mut provision_plan = MeshProvisionPlan {
        version: mesh_plan.version,
        identity_seed: mesh_plan.identity_seed,
        existing_peer_identities: Vec::new(),
        targets: provision_targets,
    };
    ensure_dynamic_proxy_export_component_routes(
        &mut provision_plan,
        &site_plan.proxy_exports,
        &plan.router_identity_id,
    )?;
    rewrite_dynamic_routed_inputs(
        &mut provision_plan,
        &site_plan.routed_inputs,
        SiteKind::Kubernetes,
        &plan.router_identity_id,
        Some(router_mesh_port),
    )?;
    let provision_existing_peer_identities =
        crate::direct_runtime::required_existing_mesh_peer_identities(
            &provision_plan,
            existing_site_peer_identities,
        )?;
    provision_plan.existing_peer_identities = provision_existing_peer_identities
        .values()
        .cloned()
        .collect();
    write_embedded_kubernetes_mesh_provision_plan(artifact_root, &provision_plan)?;
    project_dynamic_kubernetes_proxy_export_resources(
        artifact_root,
        &provision_plan,
        &site_plan.proxy_exports,
    )?;
    rewrite_dynamic_kubernetes_apply_bundle(artifact_root, &site_plan.component_ids)
}

fn kubernetes_peer_addrs_for_artifact(artifact_root: &Path) -> Result<BTreeMap<String, String>> {
    let mesh_plan = read_kubernetes_runtime_mesh_provision_plan(artifact_root)?;
    mesh_plan
        .targets
        .iter()
        .filter(|target| matches!(target.kind, MeshProvisionTargetKind::Component))
        .map(|target| {
            Ok((
                target.config.identity.id.clone(),
                kubernetes_component_mesh_peer_addr(
                    artifact_root,
                    &target.config.identity.id,
                    &target.output,
                    target.config.mesh_listen.port(),
                )?,
            ))
        })
        .collect()
}

fn build_kubernetes_route_overlay_base(
    artifact_root: &Path,
    assigned_components: &[String],
    provider_peer_addrs: &BTreeMap<String, String>,
    peer_identities: &BTreeMap<String, MeshIdentityPublic>,
) -> Result<StoredRouteOverlayPayload> {
    let mesh_plan = read_kubernetes_runtime_mesh_provision_plan(artifact_root)?;
    let kept_component_ids = assigned_components.iter().cloned().collect::<BTreeSet<_>>();
    let mut router_target = mesh_plan
        .targets
        .iter()
        .find(|target| matches!(target.kind, MeshProvisionTargetKind::Router))
        .cloned()
        .ok_or_else(|| {
            miette::miette!(
                "kubernetes artifact {} is missing a router mesh target",
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
                "kubernetes artifact {} is missing a live mesh identity for one of its route peers",
                artifact_root.display()
            )
        })?;
    Ok(StoredRouteOverlayPayload {
        peers,
        inbound_routes: router_target.config.inbound,
    })
}

fn write_kubernetes_live_route_overlay_payload(
    artifact_root: &Path,
    assigned_components: &[String],
    proxy_exports: &BTreeMap<String, DynamicProxyExportRecord>,
    routed_inputs: &[DynamicInputRouteRecord],
    peer_identities: &BTreeMap<String, MeshIdentityPublic>,
) -> Result<()> {
    let provider_peer_addrs = kubernetes_peer_addrs_for_artifact(artifact_root)?;
    let mut payload = build_kubernetes_route_overlay_base(
        artifact_root,
        assigned_components,
        &provider_peer_addrs,
        peer_identities,
    )?;
    augment_route_overlay_payload(
        &mut payload,
        proxy_exports,
        routed_inputs,
        &provider_peer_addrs,
        peer_identities,
        None,
        false,
    )?;
    write_dynamic_route_overlay_payload(artifact_root, &payload)
}

fn kubernetes_network_policy_paths_by_component_label(
    artifact_root: &Path,
) -> Result<BTreeMap<String, PathBuf>> {
    let netpol_root = artifact_root.join("05-networkpolicies");
    if !netpol_root.is_dir() {
        return Ok(BTreeMap::new());
    }
    let mut netpol_paths = BTreeMap::new();
    for path in walk_files(&netpol_root)? {
        let raw = fs::read_to_string(&path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read {}", path.display()))?;
        let document: serde_yaml::Value = serde_yaml::from_str(&raw)
            .into_diagnostic()
            .wrap_err_with(|| format!("invalid kubernetes network policy {}", path.display()))?;
        let Some(root) = document.as_mapping() else {
            continue;
        };
        if root
            .get(yaml_string("kind"))
            .and_then(serde_yaml::Value::as_str)
            != Some("NetworkPolicy")
        {
            continue;
        }
        let Some(component_label) = root
            .get(yaml_string("metadata"))
            .and_then(serde_yaml::Value::as_mapping)
            .and_then(|metadata| metadata.get(yaml_string("labels")))
            .and_then(serde_yaml::Value::as_mapping)
            .and_then(|labels| labels.get(yaml_string("amber.io/component-id")))
            .and_then(serde_yaml::Value::as_str)
        else {
            continue;
        };
        netpol_paths.insert(component_label.to_string(), path);
    }
    Ok(netpol_paths)
}

fn project_dynamic_kubernetes_proxy_export_resources(
    artifact_root: &Path,
    mesh_plan: &MeshProvisionPlan,
    proxy_exports: &BTreeMap<String, DynamicProxyExportRecord>,
) -> Result<()> {
    if proxy_exports.is_empty() {
        return Ok(());
    }

    let netpol_paths = kubernetes_network_policy_paths_by_component_label(artifact_root)?;
    let exported_mesh_ports = proxy_exports
        .values()
        .map(|export| {
            let component_target = mesh_plan
                .targets
                .iter()
                .find(|target| {
                    matches!(target.kind, MeshProvisionTargetKind::Component)
                        && target.config.identity.id == export.component
                })
                .ok_or_else(|| {
                    miette::miette!(
                        "dynamic proxy export provider {} is missing from the kubernetes mesh plan",
                        export.component
                    )
                })?;
            Ok((
                format!("c{}", export.component_id),
                component_target.config.mesh_listen.port(),
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;

    for (component_label, mesh_port) in exported_mesh_ports {
        let path = netpol_paths.get(&component_label).ok_or_else(|| {
            miette::miette!(
                "dynamic proxy export provider {component_label} is missing a kubernetes network \
                 policy in {}",
                artifact_root.join("05-networkpolicies").display()
            )
        })?;
        ensure_kubernetes_network_policy_router_ingress(path, mesh_port)?;
    }

    Ok(())
}

fn ensure_kubernetes_network_policy_router_ingress(path: &Path, mesh_port: u16) -> Result<()> {
    let raw = fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", path.display()))?;
    let mut document: serde_yaml::Value = serde_yaml::from_str(&raw)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid kubernetes network policy {}", path.display()))?;
    let root = document.as_mapping_mut().ok_or_else(|| {
        miette::miette!(
            "kubernetes network policy {} is not a YAML mapping",
            path.display()
        )
    })?;
    let spec = root
        .get_mut(yaml_string("spec"))
        .and_then(serde_yaml::Value::as_mapping_mut)
        .ok_or_else(|| {
            miette::miette!(
                "kubernetes network policy {} is missing a spec mapping",
                path.display()
            )
        })?;
    let ingress = spec
        .entry(yaml_string("ingress"))
        .or_insert_with(|| serde_yaml::Value::Sequence(Vec::new()))
        .as_sequence_mut()
        .ok_or_else(|| {
            miette::miette!(
                "kubernetes network policy {} has non-sequence spec.ingress",
                path.display()
            )
        })?;

    let router_peer = kubernetes_router_network_policy_peer();
    let mut matched_port_rule = false;
    let mut changed = false;
    for rule in ingress.iter_mut() {
        let Some(rule_mapping) = rule.as_mapping_mut() else {
            continue;
        };
        let matches_port = rule_mapping
            .get(yaml_string("ports"))
            .and_then(serde_yaml::Value::as_sequence)
            .is_some_and(|ports| {
                ports
                    .iter()
                    .any(|port| network_policy_port_matches(port, mesh_port))
            });
        if !matches_port {
            continue;
        }
        matched_port_rule = true;
        let Some(from) = rule_mapping
            .get_mut(yaml_string("from"))
            .and_then(serde_yaml::Value::as_sequence_mut)
        else {
            break;
        };
        if from.iter().any(network_policy_peer_is_router) {
            break;
        }
        from.push(router_peer.clone());
        changed = true;
        break;
    }

    if !matched_port_rule {
        ingress.push(serde_yaml::Value::Mapping(serde_yaml::Mapping::from_iter(
            [
                (
                    yaml_string("from"),
                    serde_yaml::Value::Sequence(vec![router_peer.clone()]),
                ),
                (
                    yaml_string("ports"),
                    serde_yaml::Value::Sequence(vec![serde_yaml::Value::Mapping(
                        serde_yaml::Mapping::from_iter([
                            (yaml_string("protocol"), yaml_string("TCP")),
                            (
                                yaml_string("port"),
                                serde_yaml::Value::Number(u64::from(mesh_port).into()),
                            ),
                        ]),
                    )]),
                ),
            ],
        )));
        changed = true;
    }

    if !changed {
        return Ok(());
    }

    let rendered = serde_yaml::to_string(&document)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to serialize {}", path.display()))?;
    fs::write(path, rendered)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", path.display()))
}

fn kubernetes_router_network_policy_peer() -> serde_yaml::Value {
    serde_yaml::Value::Mapping(serde_yaml::Mapping::from_iter([(
        yaml_string("podSelector"),
        serde_yaml::Value::Mapping(serde_yaml::Mapping::from_iter([(
            yaml_string("matchLabels"),
            serde_yaml::Value::Mapping(serde_yaml::Mapping::from_iter([(
                yaml_string("amber.io/component"),
                yaml_string(KUBERNETES_ROUTER_COMPONENT_NAME),
            )])),
        )])),
    )]))
}

fn network_policy_port_matches(port: &serde_yaml::Value, expected_port: u16) -> bool {
    port.as_mapping()
        .and_then(|port| port.get(yaml_string("port")))
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_i64().and_then(|value| u64::try_from(value).ok()))
        })
        == Some(u64::from(expected_port))
}

fn network_policy_peer_is_router(peer: &serde_yaml::Value) -> bool {
    peer.as_mapping()
        .and_then(|peer| peer.get(yaml_string("podSelector")))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|selector| selector.get(yaml_string("matchLabels")))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|labels| labels.get(yaml_string("amber.io/component")))
        .and_then(serde_yaml::Value::as_str)
        == Some(KUBERNETES_ROUTER_COMPONENT_NAME)
}

fn dynamic_proxy_export_kubernetes_peer_addr(
    artifact_root: &Path,
    mesh_plan: &MeshProvisionPlan,
    export: &DynamicProxyExportRecord,
) -> Result<String> {
    let component_target = mesh_plan
        .targets
        .iter()
        .find(|target| {
            matches!(target.kind, MeshProvisionTargetKind::Component)
                && target.config.identity.id == export.component
        })
        .ok_or_else(|| {
            miette::miette!(
                "dynamic proxy export provider {} is missing from the kubernetes mesh plan",
                export.component
            )
        })?;
    kubernetes_component_mesh_peer_addr(
        artifact_root,
        &export.component,
        &component_target.output,
        component_target.config.mesh_listen.port(),
    )
}

fn project_dynamic_child_mesh_scope(artifact_root: &Path, mesh_scope: Option<&str>) -> Result<()> {
    let Some(mesh_scope) = mesh_scope else {
        return Ok(());
    };
    let path = artifact_root.join("mesh-provision-plan.json");
    if path.is_file() {
        let mut plan: MeshProvisionPlan = read_json(&path, "mesh provision plan")?;
        let existing_scopes = mesh_provision_plan_scopes(&plan);
        if !project_mesh_provision_plan_scope(&mut plan, mesh_scope) {
            return Ok(());
        }
        write_json(&path, &plan)?;
        return rewrite_dynamic_artifact_mesh_scope_literals(
            artifact_root,
            &existing_scopes,
            mesh_scope,
        );
    }

    let compose_path = artifact_root.join("compose.yaml");
    if compose_path.is_file() {
        let mut plan = read_embedded_compose_mesh_provision_plan(artifact_root)?;
        let existing_scopes = mesh_provision_plan_scopes(&plan);
        if !project_mesh_provision_plan_scope(&mut plan, mesh_scope) {
            return Ok(());
        }
        write_embedded_compose_mesh_provision_plan(artifact_root, &plan)?;
        return rewrite_dynamic_artifact_mesh_scope_literals(
            artifact_root,
            &existing_scopes,
            mesh_scope,
        );
    }

    let configmap_path = artifact_root.join(KUBERNETES_MESH_PROVISION_CONFIGMAP_PATH);
    if configmap_path.is_file() {
        let mut plan = read_embedded_kubernetes_mesh_provision_plan(artifact_root)?;
        let existing_scopes = mesh_provision_plan_scopes(&plan);
        if !project_mesh_provision_plan_scope(&mut plan, mesh_scope) {
            return Ok(());
        }
        write_embedded_kubernetes_mesh_provision_plan(artifact_root, &plan)?;
        return rewrite_dynamic_artifact_mesh_scope_literals(
            artifact_root,
            &existing_scopes,
            mesh_scope,
        );
    }

    Err(miette::miette!(
        "dynamic artifact {} is missing a mesh provision plan",
        artifact_root.display()
    ))
}

fn project_mesh_provision_plan_scope(plan: &mut MeshProvisionPlan, mesh_scope: &str) -> bool {
    let mut changed = false;
    for target in &mut plan.targets {
        if target.config.identity.mesh_scope.as_deref() == Some(mesh_scope) {
            continue;
        }
        target.config.identity.mesh_scope = Some(mesh_scope.to_string());
        changed = true;
    }
    changed
}

fn mesh_provision_plan_scopes(plan: &MeshProvisionPlan) -> BTreeSet<String> {
    let mut scopes = BTreeSet::new();
    for target in &plan.targets {
        if let Some(scope) = target.config.identity.mesh_scope.as_deref() {
            scopes.insert(scope.to_string());
        }
    }
    for identity in &plan.existing_peer_identities {
        if let Some(scope) = identity.mesh_scope.as_deref() {
            scopes.insert(scope.to_string());
        }
    }
    scopes
}

fn rewrite_dynamic_artifact_mesh_scope_literals(
    artifact_root: &Path,
    existing_scopes: &BTreeSet<String>,
    mesh_scope: &str,
) -> Result<()> {
    let rewrite_scopes = existing_scopes
        .iter()
        .filter(|scope| scope.as_str() != mesh_scope)
        .cloned()
        .collect::<BTreeSet<_>>();
    if rewrite_scopes.is_empty() {
        return Ok(());
    }

    for path in walk_files(artifact_root)? {
        match path.extension().and_then(|extension| extension.to_str()) {
            Some("json") => rewrite_json_scope_literals(&path, &rewrite_scopes, mesh_scope)?,
            Some("yaml" | "yml") => {
                rewrite_yaml_scope_literals(&path, &rewrite_scopes, mesh_scope)?
            }
            Some("env") => rewrite_env_scope_literals(&path, &rewrite_scopes, mesh_scope)?,
            _ => {}
        }
    }
    Ok(())
}

fn rewrite_json_scope_literals(
    path: &Path,
    rewrite_scopes: &BTreeSet<String>,
    mesh_scope: &str,
) -> Result<()> {
    let raw = fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", path.display()))?;
    let mut document: serde_json::Value = serde_json::from_str(&raw)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid json {}", path.display()))?;
    if !rewrite_scope_json_value(&mut document, rewrite_scopes, mesh_scope) {
        return Ok(());
    }
    let rendered = serde_json::to_string_pretty(&document)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to serialize {}", path.display()))?;
    fs::write(path, rendered)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", path.display()))
}

fn rewrite_yaml_scope_literals(
    path: &Path,
    rewrite_scopes: &BTreeSet<String>,
    mesh_scope: &str,
) -> Result<()> {
    let raw = fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", path.display()))?;
    let mut document: serde_yaml::Value = serde_yaml::from_str(&raw)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid yaml {}", path.display()))?;
    if !rewrite_scope_yaml_value(&mut document, rewrite_scopes, mesh_scope) {
        return Ok(());
    }
    let rendered = serde_yaml::to_string(&document)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to serialize {}", path.display()))?;
    fs::write(path, rendered)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", path.display()))
}

fn rewrite_env_scope_literals(
    path: &Path,
    rewrite_scopes: &BTreeSet<String>,
    mesh_scope: &str,
) -> Result<()> {
    let raw = fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", path.display()))?;
    let mut changed = false;
    let mut rendered = raw
        .lines()
        .map(|line| {
            let Some((name, value)) = line.split_once('=') else {
                return line.to_string();
            };
            if !rewrite_scopes.contains(value) {
                return line.to_string();
            }
            changed = true;
            format!("{name}={mesh_scope}")
        })
        .collect::<Vec<_>>()
        .join("\n");
    if !changed {
        return Ok(());
    }
    if raw.ends_with('\n') {
        rendered.push('\n');
    }
    fs::write(path, rendered)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", path.display()))
}

fn rewrite_scope_json_value(
    value: &mut serde_json::Value,
    rewrite_scopes: &BTreeSet<String>,
    mesh_scope: &str,
) -> bool {
    match value {
        serde_json::Value::String(string) => {
            rewrite_scope_string_value(string, rewrite_scopes, mesh_scope)
        }
        serde_json::Value::Array(values) => {
            let mut changed = false;
            for value in values {
                changed |= rewrite_scope_json_value(value, rewrite_scopes, mesh_scope);
            }
            changed
        }
        serde_json::Value::Object(map) => {
            let mut changed = false;
            for value in map.values_mut() {
                changed |= rewrite_scope_json_value(value, rewrite_scopes, mesh_scope);
            }
            changed
        }
        _ => false,
    }
}

fn rewrite_scope_yaml_value(
    value: &mut serde_yaml::Value,
    rewrite_scopes: &BTreeSet<String>,
    mesh_scope: &str,
) -> bool {
    match value {
        serde_yaml::Value::String(string) => {
            rewrite_scope_string_value(string, rewrite_scopes, mesh_scope)
        }
        serde_yaml::Value::Sequence(values) => {
            let mut changed = false;
            for value in values {
                changed |= rewrite_scope_yaml_value(value, rewrite_scopes, mesh_scope);
            }
            changed
        }
        serde_yaml::Value::Mapping(map) => {
            let mut changed = false;
            for (_, value) in map.iter_mut() {
                changed |= rewrite_scope_yaml_value(value, rewrite_scopes, mesh_scope);
            }
            changed
        }
        _ => false,
    }
}

fn rewrite_scope_string_value(
    string: &mut String,
    rewrite_scopes: &BTreeSet<String>,
    mesh_scope: &str,
) -> bool {
    if rewrite_scopes.contains(string) {
        *string = mesh_scope.to_string();
        return true;
    }
    let Some((name, value)) = string.split_once('=') else {
        return false;
    };
    if !rewrite_scopes.contains(value) {
        return false;
    }
    *string = format!("{name}={mesh_scope}");
    true
}

fn reconcile_artifact_files(site_plan: &DynamicSitePlanRecord) -> &BTreeMap<String, String> {
    if site_plan.desired_artifact_files.is_empty() {
        &site_plan.artifact_files
    } else {
        &site_plan.desired_artifact_files
    }
}

fn load_kubernetes_mesh_secret_payload(
    plan: &SiteActuatorPlan,
    name: &str,
    namespace: Option<&str>,
) -> Result<(String, KubernetesSecretPayload)> {
    let namespace = namespace
        .or(plan.kubernetes_namespace.as_deref())
        .ok_or_else(|| {
            miette::miette!(
                "kubernetes site `{}` is missing its namespace",
                plan.site_id
            )
        })?
        .to_string();
    let output = kubectl_command(plan.context.as_deref())
        .arg("-n")
        .arg(&namespace)
        .arg("get")
        .arg("secret")
        .arg(name)
        .arg("-o")
        .arg("json")
        .output()
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to read kubernetes mesh secret {} in namespace {}",
                name, namespace
            )
        })?;
    if !output.status.success() {
        return Err(miette::miette!(
            "failed to read kubernetes mesh secret {} in namespace {}: {}",
            name,
            namespace,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let payload: KubernetesSecretPayload =
        serde_json::from_slice(&output.stdout).map_err(|err| {
            miette::miette!(
                "invalid kubernetes secret payload for {} in namespace {}: {err}",
                name,
                namespace
            )
        })?;
    Ok((namespace, payload))
}

fn decode_kubernetes_mesh_secret_json<T>(
    payload: &KubernetesSecretPayload,
    namespace: &str,
    name: &str,
    key: &str,
    description: &str,
) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let encoded = payload.data.get(key).ok_or_else(|| {
        miette::miette!(
            "kubernetes mesh secret {} in namespace {} is missing {}",
            name,
            namespace,
            key
        )
    })?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to decode kubernetes {description} {} in namespace {}",
                name, namespace
            )
        })?;
    serde_json::from_slice(&bytes).map_err(|err| {
        miette::miette!(
            "invalid kubernetes {description} {} in namespace {}: {err}",
            name,
            namespace
        )
    })
}

fn load_kubernetes_mesh_identity_secret(
    plan: &SiteActuatorPlan,
    name: &str,
    namespace: Option<&str>,
) -> Result<MeshIdentitySecret> {
    let (namespace, payload) = load_kubernetes_mesh_secret_payload(plan, name, namespace)?;
    decode_kubernetes_mesh_secret_json(
        &payload,
        &namespace,
        name,
        MESH_IDENTITY_FILENAME,
        "mesh identity",
    )
}

fn load_kubernetes_mesh_config_public(
    plan: &SiteActuatorPlan,
    name: &str,
    namespace: Option<&str>,
) -> Result<MeshConfigPublic> {
    let (namespace, payload) = load_kubernetes_mesh_secret_payload(plan, name, namespace)?;
    decode_kubernetes_mesh_secret_json(
        &payload,
        &namespace,
        name,
        MESH_CONFIG_FILENAME,
        "mesh config",
    )
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
    let runtime_root = site_actuator_child_runtime_root(plan, child.child_id);
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

fn dynamic_child_route_overlay_id(plan: &SiteActuatorPlan, child_id: u64) -> String {
    format!("framework-child:{}:{child_id}", plan.site_id)
}

fn site_router_control_endpoint(plan: &SiteActuatorPlan) -> Result<ControlEndpoint> {
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

fn child_router_overlay_payload(
    plan: &SiteActuatorPlan,
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
                runtime_config.mesh_listen,
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
            *peer_addr = resolved.to_string();
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

fn child_overlay_runtime_root(plan: &SiteActuatorPlan, child: &SiteActuatorChildRecord) -> PathBuf {
    match plan.kind {
        SiteKind::Direct | SiteKind::Vm => site_actuator_child_runtime_root(plan, child.child_id),
        SiteKind::Compose | SiteKind::Kubernetes => PathBuf::from(&child.artifact_root),
    }
}

fn dynamic_route_issuer_grants(
    children: &[SiteActuatorChildRecord],
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

fn load_published_component_peers(
    plan: &SiteActuatorPlan,
    published_children: &[SiteActuatorChildRecord],
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

fn apply_dynamic_route_issuer_grants(
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

async fn reconcile_dynamic_site_router_overlays(app: &SiteActuatorApp) -> Result<()> {
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

async fn reconcile_dynamic_site_router_overlays_for_children(
    app: &SiteActuatorApp,
    overlay_children: &[SiteActuatorChildRecord],
    issuer_children: &[SiteActuatorChildRecord],
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

async fn apply_dynamic_site_router_overlay(
    plan: &SiteActuatorPlan,
    child: &SiteActuatorChildRecord,
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

async fn revoke_dynamic_site_router_overlay(
    plan: &SiteActuatorPlan,
    child: &SiteActuatorChildRecord,
) -> Result<()> {
    let endpoint = site_router_control_endpoint(plan)?;
    revoke_route_overlay_with_retry(
        &endpoint,
        &dynamic_child_route_overlay_id(plan, child.child_id),
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
    let published_children = {
        let state = app.state.lock().await;
        state
            .children
            .values()
            .filter(|child| child.published)
            .cloned()
            .collect::<Vec<_>>()
    };
    replace_artifact_snapshot(&artifact_root, &site_plan.artifact_files)?;
    project_dynamic_child_mesh_scope(&artifact_root, Some(&app.plan.mesh_scope))?;
    if site_plan.kind == SiteKind::Kubernetes {
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
        site_plan.kind,
        &app.plan.launch_env,
        app.plan.observability_endpoint.as_deref(),
    )?;
    match site_plan.kind {
        SiteKind::Direct => {
            filter_direct_stage_plan(&artifact_root, &site_plan.component_ids)?;
            ensure_dynamic_proxy_export_component_routes_in_artifact(
                &artifact_root,
                &site_plan.proxy_exports,
                &app.plan.router_identity_id,
            )?;
            rewrite_dynamic_routed_inputs_in_artifact(
                &artifact_root,
                &site_plan,
                app.plan.router_mesh_port,
            )?;
            write_direct_vm_startup_route_overlay_payload(
                &artifact_root,
                "direct",
                &site_plan.routed_inputs,
                &overlay_peer_addr_map_from_ports(&local_direct_peer_ports_for_children(
                    &app.plan,
                    &published_children,
                )?),
                &local_direct_peer_identities_for_children(&app.plan, &published_children)?,
            )?;
        }
        SiteKind::Vm => {
            filter_vm_stage_plan(&artifact_root, &site_plan.component_ids)?;
            ensure_dynamic_proxy_export_component_routes_in_artifact(
                &artifact_root,
                &site_plan.proxy_exports,
                &app.plan.router_identity_id,
            )?;
            rewrite_dynamic_routed_inputs_in_artifact(
                &artifact_root,
                &site_plan,
                app.plan.router_mesh_port,
            )?;
            write_direct_vm_startup_route_overlay_payload(
                &artifact_root,
                "vm",
                &site_plan.routed_inputs,
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
                &site_plan,
                &artifact_root,
                &published_children,
                &existing_peer_identities,
            )?
        }
        SiteKind::Kubernetes => {
            let existing_peer_identities =
                local_kubernetes_peer_identities(&app.plan, &published_children)?;
            prepare_dynamic_kubernetes_child_artifact(
                &app.plan,
                &site_plan,
                &artifact_root,
                &existing_peer_identities,
            )?
        }
    }
    write_dynamic_proxy_exports_metadata(&artifact_root, &site_plan.proxy_exports)?;
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
            assigned_components: site_plan.assigned_components.clone(),
            proxy_exports: site_plan.proxy_exports.clone(),
            routed_inputs: site_plan.routed_inputs.clone(),
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
    let (child, published_children) = {
        let state = app.state.lock().await;
        let child = state
            .children
            .get(&child_id)
            .cloned()
            .ok_or_else(|| miette::miette!("site actuator child {child_id} is not prepared"))?;
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
            if dynamic_route_overlay_path(Path::new(&child.artifact_root)).is_file() {
                apply_dynamic_site_router_overlay(&app.plan, &child).await?;
            }
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
            reconcile_site_proxy_metadata(Path::new(&app.plan.artifact_dir), &site_plan)?;
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
            if dynamic_route_overlay_path(Path::new(&child.artifact_root)).is_file() {
                apply_dynamic_site_router_overlay(&app.plan, &child).await?;
            }
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
            reconcile_site_proxy_metadata(Path::new(&app.plan.artifact_dir), &site_plan)?;
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
            wait_for_kubernetes_site_router_ready(
                &app.plan,
                site_ready_timeout_for_kind(SiteKind::Kubernetes),
            )
            .await?;
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
        && matches!(
            app.plan.kind,
            SiteKind::Direct | SiteKind::Vm | SiteKind::Compose | SiteKind::Kubernetes
        )
    {
        revoke_dynamic_site_router_overlay(
            &app.plan,
            child
                .as_ref()
                .expect("published child should be available for overlay revoke"),
        )
        .await?;
    }
    if let Some(pid) = child.as_ref().and_then(|child| child.process_pid) {
        terminate_pid(pid, site_ready_timeout_for_kind(app.plan.kind))?;
    }

    match app.plan.kind {
        SiteKind::Compose => {
            let _ = desired_site_plan;
            let child = child
                .as_ref()
                .ok_or_else(|| miette::miette!("site actuator child {child_id} is not prepared"))?;
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
            let _ = desired_site_plan;
            let child = child
                .as_ref()
                .ok_or_else(|| miette::miette!("site actuator child {child_id} is not prepared"))?;
            let artifact_root = Path::new(&child.artifact_root);
            let files = read_artifact_snapshot(artifact_root)?;
            let destroy_bundle = project_kubernetes_dynamic_child_destroy_artifact_files(&files)?;
            replace_artifact_snapshot(artifact_root, &destroy_bundle)?;
            let supervisor_plan = prepare_kubernetes_artifact_for_apply(&app.plan, artifact_root)?;
            let workloads = supervisor::kubernetes_expected_workloads(artifact_root)?;
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
            if let Some(desired) = desired_site_plan.as_ref() {
                reconcile_site_proxy_metadata(Path::new(&app.plan.artifact_dir), desired)?;
            }
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
    }
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

fn wait_for_named_kubernetes_resource_deleted(
    context: Option<&str>,
    namespace: &str,
    resource_kind: &str,
    name: &str,
    label: &str,
) -> Result<()> {
    let resource = format!("{resource_kind}/{name}");
    let timeout = format!("{}s", KUBERNETES_WORKLOAD_READY_TIMEOUT.as_secs().max(1));
    let output = kubectl_command(context)
        .args([
            "-n",
            namespace,
            "wait",
            "--for=delete",
            "--timeout",
            timeout.as_str(),
            resource.as_str(),
        ])
        .output()
        .into_diagnostic()
        .wrap_err_with(|| format!("{label}: wait for {resource} deletion"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.contains("not found") {
        return Ok(());
    }
    let detail = if stderr.is_empty() {
        format!("status {}", output.status)
    } else {
        stderr
    };
    Err(miette::miette!("{label} failed: {detail}"))
}

fn wait_for_kubernetes_artifact_workloads_deleted(
    context: Option<&str>,
    namespace: &str,
    workloads: &supervisor::KubernetesArtifactWorkloads,
    site_id: &str,
) -> Result<()> {
    let label = format!("wait for kubernetes child workload deletion on site `{site_id}`");
    for job in &workloads.jobs {
        wait_for_named_kubernetes_resource_deleted(context, namespace, "job", job, &label)?;
    }
    for deployment in &workloads.deployments {
        wait_for_named_kubernetes_resource_deleted(
            context,
            namespace,
            "deployment",
            deployment,
            &label,
        )?;
    }
    Ok(())
}

async fn wait_for_kubernetes_site_router_ready(
    plan: &SiteActuatorPlan,
    timeout: Duration,
) -> Result<()> {
    debug_assert_eq!(plan.kind, SiteKind::Kubernetes);

    let state_path = Path::new(&plan.site_state_root).join("manager-state.json");
    let deadline = Instant::now() + timeout;
    loop {
        if state_path.is_file() {
            let state: SiteManagerState = read_json(&state_path, "site manager state")?;
            if matches!(state.status, SiteLifecycleStatus::Failed) {
                return Err(miette::miette!(
                    "kubernetes site `{}` failed while waiting for router recovery: {}",
                    plan.site_id,
                    state
                        .last_error
                        .unwrap_or_else(|| "unknown failure".to_string())
                ));
            }
            if matches!(state.status, SiteLifecycleStatus::Running)
                && let (Some(control), Some(mesh_addr)) = (
                    state.router_control.as_deref(),
                    state.router_mesh_addr.as_deref(),
                )
            {
                let control_addr: SocketAddr =
                    control.parse().into_diagnostic().wrap_err_with(|| {
                        format!("invalid kubernetes router control addr `{control}`")
                    })?;
                let mesh_addr: SocketAddr =
                    mesh_addr.parse().into_diagnostic().wrap_err_with(|| {
                        format!("invalid kubernetes router mesh addr `{mesh_addr}`")
                    })?;
                if probe_kubernetes_router_identity(control_addr, Duration::from_millis(250))
                    .await?
                    && router_mesh_listener_ready(mesh_addr).await
                {
                    return Ok(());
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(miette::miette!(
                "timed out waiting for kubernetes site `{}` router recovery",
                plan.site_id
            ));
        }
        sleep(Duration::from_millis(200)).await;
    }
}

async fn probe_kubernetes_router_identity(addr: SocketAddr, timeout: Duration) -> Result<bool> {
    let mut stream = match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(err))
            if matches!(
                err.kind(),
                std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::NotConnected
            ) =>
        {
            return Ok(false);
        }
        Ok(Err(err)) => {
            return Err(miette::miette!(
                "failed to connect to kubernetes router control at {addr}: {err}"
            ));
        }
        Err(_) => return Ok(false),
    };

    let request = b"GET /identity HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    match tokio::time::timeout(timeout, stream.write_all(request)).await {
        Ok(Ok(())) => {}
        Ok(Err(err))
            if matches!(
                err.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::NotConnected
            ) =>
        {
            return Ok(false);
        }
        Ok(Err(err)) => {
            return Err(miette::miette!(
                "failed to write kubernetes router identity probe to {addr}: {err}"
            ));
        }
        Err(_) => return Ok(false),
    }

    let deadline = Instant::now() + timeout;
    let mut buf = Vec::new();
    loop {
        if let Some(end) = find_header_end(&buf)
            && let Some(content_length) = router_identity_probe_content_length(&buf[..end])?
        {
            let body_len = buf.len().saturating_sub(end + 4);
            if body_len >= content_length {
                return parse_router_identity_probe_response(&buf, end);
            }
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Ok(false);
        };
        let mut chunk = [0u8; 1024];
        match tokio::time::timeout(remaining, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => return Ok(false),
            Ok(Ok(read)) => buf.extend_from_slice(&chunk[..read]),
            Ok(Err(err))
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::NotConnected
                ) =>
            {
                return Ok(false);
            }
            Ok(Err(err)) => {
                return Err(miette::miette!(
                    "failed to read kubernetes router identity probe from {addr}: {err}"
                ));
            }
            Err(_) => return Ok(false),
        }
    }
}

fn router_identity_probe_content_length(header: &[u8]) -> Result<Option<usize>> {
    let header = std::str::from_utf8(header)
        .into_diagnostic()
        .wrap_err("router identity probe returned a non-UTF-8 HTTP header")?;
    Ok(header.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then_some(value.trim())
            .and_then(|value| value.parse::<usize>().ok())
    }))
}

fn parse_router_identity_probe_response(buf: &[u8], header_end: usize) -> Result<bool> {
    let header = std::str::from_utf8(&buf[..header_end])
        .into_diagnostic()
        .wrap_err("router identity probe returned a non-UTF-8 HTTP header")?;
    let status = header
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok());
    if status != Some(200) {
        return Ok(false);
    }
    let body = std::str::from_utf8(&buf[header_end + 4..])
        .into_diagnostic()
        .wrap_err("router identity probe returned a non-UTF-8 body")?;
    Ok(serde_json::from_str::<MeshIdentityPublic>(body.trim()).is_ok())
}

fn filter_direct_stage_plan(artifact_root: &Path, component_ids: &[usize]) -> Result<()> {
    let keep = component_ids.iter().copied().collect::<BTreeSet<_>>();
    let plan_path = artifact_root.join("direct-plan.json");
    let mut plan: DirectPlan = read_json(&plan_path, "direct plan")?;
    plan.components
        .retain(|component| keep.contains(&component.id));
    plan.startup_order
        .retain(|component_id| keep.contains(component_id));
    filter_dynamic_runtime_addresses(&mut plan.runtime_addresses, &keep);
    let keep_mesh_output_dirs = plan
        .components
        .iter()
        .filter_map(|component| {
            Path::new(&component.sidecar.mesh_config_path)
                .parent()
                .map(path_to_forward_slash_string)
        })
        .collect::<BTreeSet<_>>();
    plan.router = None;
    write_json(&plan_path, &plan)?;
    filter_dynamic_mesh_provision_plan(artifact_root, &keep_mesh_output_dirs)
}

fn filter_vm_stage_plan(artifact_root: &Path, component_ids: &[usize]) -> Result<()> {
    let keep = component_ids.iter().copied().collect::<BTreeSet<_>>();
    let plan_path = artifact_root.join("vm-plan.json");
    let mut plan: VmPlan = read_json(&plan_path, "vm plan")?;
    plan.components
        .retain(|component| keep.contains(&component.id));
    plan.startup_order
        .retain(|component_id| keep.contains(component_id));
    filter_dynamic_runtime_addresses(&mut plan.runtime_addresses, &keep);
    let keep_mesh_output_dirs = plan
        .components
        .iter()
        .filter_map(|component| {
            Path::new(&component.mesh_config_path)
                .parent()
                .map(path_to_forward_slash_string)
        })
        .collect::<BTreeSet<_>>();
    plan.router = None;
    write_json(&plan_path, &plan)?;
    filter_dynamic_mesh_provision_plan(artifact_root, &keep_mesh_output_dirs)
}

fn filter_dynamic_runtime_addresses(
    runtime_addresses: &mut amber_compiler::reporter::direct::DirectRuntimeAddressPlan,
    keep: &BTreeSet<usize>,
) {
    runtime_addresses
        .slots_by_scope
        .retain(|scope, _| keep.contains(scope));
    for sources in runtime_addresses.slots_by_scope.values_mut() {
        sources.retain(|_, source| keep.contains(&dynamic_runtime_source_component_id(source)));
    }
    runtime_addresses
        .slot_items_by_scope
        .retain(|scope, _| keep.contains(scope));
    for sources in runtime_addresses.slot_items_by_scope.values_mut() {
        sources.retain(|_, items| {
            items.retain(|source| keep.contains(&dynamic_runtime_source_component_id(source)));
            !items.is_empty()
        });
    }
}

fn dynamic_runtime_source_component_id(source: &DirectRuntimeUrlSource) -> usize {
    match source {
        DirectRuntimeUrlSource::Slot { component_id, .. }
        | DirectRuntimeUrlSource::SlotItem { component_id, .. } => *component_id,
    }
}

fn path_to_forward_slash_string(path: &Path) -> String {
    path.components()
        .fold(String::new(), |mut rendered, component| {
            if !rendered.is_empty() {
                rendered.push('/');
            }
            rendered.push_str(&component.as_os_str().to_string_lossy());
            rendered
        })
}

fn filter_dynamic_mesh_provision_plan(
    artifact_root: &Path,
    keep_component_output_dirs: &BTreeSet<String>,
) -> Result<()> {
    let plan_path = artifact_root.join("mesh-provision-plan.json");
    let mut plan: MeshProvisionPlan = read_json(&plan_path, "mesh provision plan")?;
    let mut kept_component_ids = BTreeSet::new();
    let mut router_target = None;
    let mut filtered_targets = Vec::with_capacity(plan.targets.len());
    for target in plan.targets {
        match target.kind {
            MeshProvisionTargetKind::Component => {
                let MeshProvisionOutput::Filesystem { dir } = &target.output else {
                    return Err(miette::miette!(
                        "dynamic mesh target {} does not use filesystem output",
                        target.config.identity.id
                    ));
                };
                if keep_component_output_dirs.contains(dir) {
                    kept_component_ids.insert(target.config.identity.id.clone());
                    filtered_targets.push(target);
                }
            }
            MeshProvisionTargetKind::Router => {
                router_target = Some(target);
            }
        }
    }

    let Some(mut router_target) = router_target else {
        return Err(miette::miette!(
            "dynamic mesh provision plan {} is missing a router target",
            plan_path.display()
        ));
    };
    filter_dynamic_router_target(&mut router_target, &kept_component_ids);
    filtered_targets.push(router_target);
    plan.targets = filtered_targets;
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

fn wait_for_detached_vm_child_endpoints_ready(
    pid: u32,
    artifact_root: &Path,
    runtime_root: &Path,
    timeout: Duration,
    log_path: &Path,
) -> Result<()> {
    let plan: VmPlan = read_json(&artifact_root.join("vm-plan.json"), "vm plan")?;
    let deadline = Instant::now() + timeout;
    for component in &plan.components {
        let config: MeshConfigPublic = read_json(
            &runtime_root.join(&component.mesh_config_path),
            "mesh config",
        )?;
        for route in config.inbound {
            let InboundTarget::Local { port: host_port } = route.target else {
                continue;
            };
            let addr = SocketAddr::from(([127, 0, 0, 1], host_port));
            loop {
                let ready = match route.protocol {
                    MeshProtocol::Http => endpoint_returns_http_response(
                        addr,
                        Duration::from_millis(250),
                        Duration::from_millis(250),
                    ),
                    MeshProtocol::Tcp => endpoint_accepts_stable_connection(
                        addr,
                        Duration::from_millis(250),
                        Duration::from_millis(250),
                    ),
                };
                if ready {
                    break;
                }
                if !pid_is_alive(pid) {
                    let log = fs::read_to_string(log_path).unwrap_or_default();
                    return Err(miette::miette!(
                        "dynamic vm child runtime exited before component {} endpoint {} became \
                         ready\nlog ({}):\n{}",
                        component.moniker,
                        addr,
                        log_path.display(),
                        log
                    ));
                }
                if Instant::now() >= deadline {
                    let log = fs::read_to_string(log_path).unwrap_or_default();
                    let protocol = match route.protocol {
                        MeshProtocol::Http => "http",
                        MeshProtocol::Tcp => "tcp",
                    };
                    return Err(miette::miette!(
                        "timed out waiting for dynamic vm child component {} {} endpoint {} to \
                         become ready\nlog ({}):\n{}",
                        component.moniker,
                        protocol,
                        addr,
                        log_path.display(),
                        log
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    Ok(())
}

fn local_direct_peer_ports(
    plan: &SiteActuatorPlan,
    state: &SiteActuatorState,
) -> Result<BTreeMap<String, u16>> {
    let children = state
        .children
        .values()
        .filter(|child| child.published)
        .cloned()
        .collect::<Vec<_>>();
    local_direct_peer_ports_for_children(plan, &children)
}

fn local_direct_peer_ports_for_children(
    plan: &SiteActuatorPlan,
    children: &[SiteActuatorChildRecord],
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
    for child in children {
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
    let children = state
        .children
        .values()
        .filter(|child| child.published)
        .cloned()
        .collect::<Vec<_>>();
    local_direct_peer_identities_for_children(plan, &children)
}

fn local_direct_peer_identities_for_children(
    plan: &SiteActuatorPlan,
    children: &[SiteActuatorChildRecord],
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
    for child in children {
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
    let children = state
        .children
        .values()
        .filter(|child| child.published)
        .cloned()
        .collect::<Vec<_>>();
    local_vm_peer_ports_for_children(plan, &children)
}

fn local_vm_peer_ports_for_children(
    plan: &SiteActuatorPlan,
    children: &[SiteActuatorChildRecord],
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
    for child in children {
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
    let children = state
        .children
        .values()
        .filter(|child| child.published)
        .cloned()
        .collect::<Vec<_>>();
    local_vm_peer_identities_for_children(plan, &children)
}

fn local_vm_peer_identities_for_children(
    plan: &SiteActuatorPlan,
    children: &[SiteActuatorChildRecord],
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
    for child in children {
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
    let state = load_vm_runtime_state_for_artifact(artifact_root, runtime_root)?;
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

fn load_vm_runtime_state_for_artifact(
    artifact_root: &Path,
    runtime_root: &Path,
) -> Result<VmRuntimeState> {
    let state_path = artifact_root.join(".amber").join("vm-runtime.json");
    if state_path.is_file() {
        return read_json(&state_path, "vm runtime state");
    }

    let plan: VmPlan = read_json(&artifact_root.join("vm-plan.json"), "vm plan")?;
    let mut state = VmRuntimeState::default();
    for component in &plan.components {
        let config: MeshConfigPublic = read_json(
            &runtime_root.join(&component.mesh_config_path),
            "mesh config",
        )?;
        state
            .component_mesh_port_by_id
            .insert(component.id, config.mesh_listen.port());
    }
    if let Some(router) = &plan.router {
        let config: MeshConfigPublic =
            read_json(&runtime_root.join(&router.mesh_config_path), "mesh config")?;
        state.router_mesh_port = Some(config.mesh_listen.port());
    }
    write_vm_runtime_state(artifact_root, &state)?;
    Ok(state)
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
    #[cfg(unix)]
    {
        terminate_detached_runtime(pid, timeout)
    }

    #[cfg(not(unix))]
    {
        send_sigterm(pid);
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if !pid_is_alive(pid) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Ok(())
    }
}

#[cfg(unix)]
fn terminate_detached_runtime(root_pid: u32, timeout: Duration) -> Result<()> {
    let mut tracked = process_tree_postorder(root_pid)?
        .into_iter()
        .filter(|pid| pid_is_alive(*pid))
        .collect::<Vec<_>>();
    if tracked.is_empty() {
        return Ok(());
    }

    send_signal_to_process_group(root_pid, libc::SIGTERM);
    send_signal_to_pids(&tracked, libc::SIGTERM);

    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        tracked.retain(|pid| pid_is_alive(*pid));
        if tracked.is_empty() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    send_signal_to_process_group(root_pid, libc::SIGKILL);
    send_signal_to_pids(&tracked, libc::SIGKILL);

    let force_deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < force_deadline {
        tracked.retain(|pid| pid_is_alive(*pid));
        if tracked.is_empty() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    Err(miette::miette!(
        "failed to terminate detached runtime rooted at pid {root_pid}; surviving processes: {}",
        tracked
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ))
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
    artifact_dir: &Path,
    kubernetes_namespace: Option<String>,
) -> SiteSupervisorPlan {
    SiteSupervisorPlan {
        schema: SITE_PLAN_SCHEMA.to_string(),
        version: SITE_PLAN_VERSION,
        run_id: plan.run_id.clone(),
        mesh_scope: plan.mesh_scope.clone(),
        run_root: plan.run_root.clone(),
        coordinator_pid: 0,
        site_id: plan.site_id.clone(),
        kind: plan.kind,
        artifact_dir: artifact_dir.display().to_string(),
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

fn prepare_kubernetes_artifact_for_apply(
    plan: &SiteActuatorPlan,
    artifact_dir: &Path,
) -> Result<SiteSupervisorPlan> {
    debug_assert_eq!(plan.kind, SiteKind::Kubernetes);
    let namespace =
        prepare_kubernetes_artifact_namespace(&plan.run_id, &plan.site_id, artifact_dir)?;
    patch_site_artifacts(
        artifact_dir,
        &plan.run_id,
        &plan.site_id,
        plan.kind,
        &plan.launch_env,
        plan.observability_endpoint.as_deref(),
    )?;
    Ok(site_supervisor_plan_for_actuator(
        plan,
        artifact_dir,
        Some(namespace),
    ))
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

async fn wait_for_compose_services_running(
    compose_project: &str,
    artifact_root: &Path,
    services: &[String],
    timeout: Duration,
) -> Result<()> {
    if services.is_empty() {
        return Ok(());
    }
    let deadline = Instant::now() + timeout;
    loop {
        let output = compose_command(Some(compose_project), artifact_root)
            .arg("ps")
            .arg("--services")
            .arg("--status")
            .arg("running")
            .args(services)
            .output()
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "failed to query compose child services in {}",
                    artifact_root.display()
                )
            })?;
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            let running = stdout
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .collect::<BTreeSet<_>>();
            if services
                .iter()
                .all(|service| running.contains(service.as_str()))
            {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err(miette::miette!(
                "timed out waiting for compose child services {:?} in {}",
                services,
                artifact_root.display()
            ));
        }
        sleep(Duration::from_millis(200)).await;
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

#[cfg(unix)]
fn send_signal_to_pids(pids: &[u32], signal: i32) {
    for pid in pids {
        let Some(pid) = i32::try_from(*pid).ok() else {
            continue;
        };
        let _ = unsafe { libc::kill(pid, signal) };
    }
}

#[cfg(unix)]
fn send_signal_to_process_group(root_pid: u32, signal: i32) {
    let Some(root_pid) = i32::try_from(root_pid).ok() else {
        return;
    };
    let _ = unsafe { libc::kill(-root_pid, signal) };
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
