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

pub(crate) fn dry_run_run_plan(
    source_plan_path: Option<&Path>,
    run_plan: &RunPlan,
    bundle_root: &Path,
    observability: Option<&str>,
    runtime_env: &BTreeMap<String, String>,
) -> Result<PathBuf> {
    if bundle_root.exists() {
        return Err(miette::miette!(
            "launch bundle output directory `{}` already exists",
            bundle_root.display()
        ));
    }
    fs::create_dir_all(bundle_root)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create launch bundle output directory {}",
                bundle_root.display()
            )
        })?;
    let run_id = new_run_id();
    materialize_launch_bundle(
        source_plan_path,
        run_plan,
        bundle_root,
        &run_id,
        observability,
        runtime_env,
    )?;
    Ok(bundle_root.to_path_buf())
}

fn materialize_launch_bundle(
    source_plan_path: Option<&Path>,
    run_plan: &RunPlan,
    bundle_root: &Path,
    run_id: &str,
    observability: Option<&str>,
    runtime_env: &BTreeMap<String, String>,
) -> Result<MaterializedLaunchBundle> {
    let sites_root = bundle_root.join("sites");
    let state_root = bundle_root.join("state");
    fs::create_dir_all(&sites_root)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create run directory {}", sites_root.display()))?;
    fs::create_dir_all(&state_root)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create state directory {}", state_root.display()))?;

    let run_plan_path = run_plan_path(bundle_root);
    write_json(&run_plan_path, run_plan)?;

    let observability =
        materialize_observability(bundle_root, run_id, &run_plan.mesh_scope, observability)?;
    let observability_endpoint = observability
        .as_ref()
        .map(|materialized| materialized.receipt.endpoint.as_str());

    let mut sites = BTreeMap::new();
    for (site_id, site_plan) in &run_plan.sites {
        let artifact_dir = materialize_site_artifacts(&sites_root, site_id, site_plan)?;
        patch_site_artifacts(
            &artifact_dir,
            site_plan.site.kind,
            runtime_env,
            observability_endpoint,
        )?;
        let site_state_root = state_root.join(site_id);
        let base_supervisor_plan = build_supervisor_plan(
            SupervisorPlanInput {
                run_root: bundle_root,
                run_id,
                mesh_scope: &run_plan.mesh_scope,
                site_id,
                site_plan,
                artifact_dir: &artifact_dir,
                site_state_root: &site_state_root,
                observability_endpoint,
            },
            launch_env(
                run_id,
                &run_plan.mesh_scope,
                site_plan.site.kind,
                runtime_env,
                &BTreeMap::new(),
                observability_endpoint,
            )?,
        )?;
        write_json(
            &site_supervisor_plan_path(&site_state_root),
            &base_supervisor_plan,
        )?;
        write_json(
            &desired_links_path(&site_state_root),
            &DesiredLinkState {
                schema: DESIRED_LINKS_SCHEMA.to_string(),
                version: DESIRED_LINKS_VERSION,
                external_slots: BTreeMap::new(),
                export_peers: Vec::new(),
            },
        )?;
        sites.insert(
            site_id.clone(),
            MaterializedSite {
                site_plan: site_plan.clone(),
                artifact_dir,
                site_state_root,
                base_supervisor_plan,
            },
        );
    }

    let manifest = build_launch_bundle_manifest(
        run_id,
        source_plan_path,
        run_plan,
        bundle_root,
        &run_plan_path,
        observability.as_ref(),
        &sites,
    )?;
    write_json(&launch_bundle_manifest_path(bundle_root), &manifest)?;

    Ok(MaterializedLaunchBundle {
        run_plan_path,
        observability,
        sites,
    })
}

fn build_launch_bundle_manifest(
    run_id: &str,
    source_plan_path: Option<&Path>,
    run_plan: &RunPlan,
    bundle_root: &Path,
    run_plan_path: &Path,
    observability: Option<&MaterializedObservability>,
    sites: &BTreeMap<String, MaterializedSite>,
) -> Result<LaunchBundleManifest> {
    let mut site_entries = BTreeMap::new();
    let mut site_contexts = BTreeMap::new();
    for (site_id, site) in sites {
        let mut dynamic_external_slots = run_plan
            .links
            .iter()
            .filter(|link| link.consumer_site == *site_id)
            .map(|link| link.external_slot_name.clone())
            .collect::<Vec<_>>();
        dynamic_external_slots.sort();
        dynamic_external_slots.dedup();
        let preview = match site_launch_preview(&site.base_supervisor_plan) {
            Ok(preview) => preview,
            Err(err) => SiteLaunchPreviewBundle {
                inspectability_warnings: vec![format!(
                    "failed to inspect site launch details: {err}"
                )],
                ..Default::default()
            },
        };
        site_contexts.insert(
            site_id.clone(),
            SiteStitchContext {
                kind: site.site_plan.site.kind,
                router_identity_id: site.site_plan.router_identity_id.clone(),
                router_public_key_b64: preview.router_public_key_b64.clone(),
                router_mesh_port: site.base_supervisor_plan.router_mesh_port,
            },
        );
        site_entries.insert(
            site_id.clone(),
            LaunchBundleSite {
                kind: site.site_plan.site.kind,
                router_identity_id: site.site_plan.router_identity_id.clone(),
                router_public_key_b64: preview.router_public_key_b64,
                assigned_components: site.site_plan.assigned_components.clone(),
                artifact_dir: site.artifact_dir.display().to_string(),
                site_state_root: site.site_state_root.display().to_string(),
                supervisor_plan_path: site_supervisor_plan_path(&site.site_state_root)
                    .display()
                    .to_string(),
                desired_links_path: desired_links_path(&site.site_state_root)
                    .display()
                    .to_string(),
                dynamic_external_slots,
                launch_commands: site_launch_commands(&site.base_supervisor_plan)?,
                processes: preview.processes,
                virtual_machines: preview.virtual_machines,
                inspectability_warnings: preview.inspectability_warnings,
            },
        );
    }

    let observability = observability
        .map(|observability| -> Result<LaunchBundleObservability> {
            Ok(LaunchBundleObservability {
                endpoint: observability.receipt.endpoint.clone(),
                plan_path: observability
                    .plan_path
                    .as_ref()
                    .map(|path| path.display().to_string()),
                state_path: observability
                    .plan_path
                    .as_ref()
                    .map(|_| observability_state_path(bundle_root).display().to_string()),
                requests_log: observability.receipt.requests_log.clone(),
                launch_commands: observability_launch_commands(observability)?,
            })
        })
        .transpose()?;

    Ok(LaunchBundleManifest {
        schema: LAUNCH_BUNDLE_SCHEMA.to_string(),
        version: LAUNCH_BUNDLE_VERSION,
        run_id: run_id.to_string(),
        mesh_scope: run_plan.mesh_scope.clone(),
        plan_path: run_plan_path.display().to_string(),
        source_plan_path: source_plan_path.map(|path| path.display().to_string()),
        bundle_root: bundle_root.display().to_string(),
        assignments: run_plan.assignments.clone(),
        startup_waves: run_plan.startup_waves.clone(),
        stitching: build_launch_bundle_stitching_preview(run_plan, &site_contexts)?,
        observability,
        sites: site_entries,
    })
}

fn site_launch_preview(plan: &SiteSupervisorPlan) -> Result<SiteLaunchPreviewBundle> {
    Ok(match plan.kind {
        SiteKind::Direct => {
            let preview: DirectSiteLaunchPreview = build_direct_site_launch_preview(
                &PathBuf::from(&plan.artifact_dir).join("direct-plan.json"),
                Path::new(required_path(
                    plan.storage_root.as_deref(),
                    "direct storage root",
                )),
                Path::new(required_path(
                    plan.runtime_root.as_deref(),
                    "direct runtime root",
                )),
                plan.router_mesh_port,
            )?;
            SiteLaunchPreviewBundle {
                router_public_key_b64: preview.router_public_key_b64,
                processes: preview.processes,
                virtual_machines: Vec::new(),
                inspectability_warnings: Vec::new(),
            }
        }
        SiteKind::Vm => {
            let preview: VmSiteLaunchPreview = build_vm_site_launch_preview(
                &PathBuf::from(&plan.artifact_dir).join("vm-plan.json"),
                Path::new(required_path(
                    plan.storage_root.as_deref(),
                    "vm storage root",
                )),
                Path::new(required_path(
                    plan.runtime_root.as_deref(),
                    "vm runtime root",
                )),
                plan.router_mesh_port,
            )?;
            SiteLaunchPreviewBundle {
                router_public_key_b64: preview.router_public_key_b64,
                processes: Vec::new(),
                virtual_machines: preview.virtual_machines,
                inspectability_warnings: preview.inspectability_warnings,
            }
        }
        SiteKind::Compose | SiteKind::Kubernetes => SiteLaunchPreviewBundle::default(),
    })
}

fn build_launch_bundle_stitching_preview(
    run_plan: &RunPlan,
    site_contexts: &BTreeMap<String, SiteStitchContext>,
) -> Result<Vec<LaunchBundleLinkPreview>> {
    run_plan
        .links
        .iter()
        .map(|link| {
            let provider = site_contexts.get(&link.provider_site).ok_or_else(|| {
                miette::miette!(
                    "launch bundle is missing provider site `{}`",
                    link.provider_site
                )
            })?;
            let consumer = site_contexts.get(&link.consumer_site).ok_or_else(|| {
                miette::miette!(
                    "launch bundle is missing consumer site `{}`",
                    link.consumer_site
                )
            })?;
            let preview_external_url = match (
                provider.router_mesh_port,
                provider.router_public_key_b64.as_deref(),
            ) {
                (Some(port), Some(peer_key_b64)) => Some(preview_external_slot_url(
                    port,
                    peer_key_b64,
                    &provider.router_identity_id,
                    link,
                    provider.kind,
                    consumer.kind,
                )?),
                _ => None,
            };
            let (resolution, unresolved_reason) = if preview_external_url.is_some() {
                (LaunchBundleLinkResolution::Exact, None)
            } else {
                let reason = match provider.kind {
                    SiteKind::Compose => {
                        "compose router host ports are assigned when Docker starts the site"
                    }
                    SiteKind::Kubernetes => {
                        "kubernetes router addresses are discovered after the port-forward sidecar \
                         starts"
                    }
                    SiteKind::Direct | SiteKind::Vm => {
                        "provider runtime identity and mesh address are materialized during launch"
                    }
                };
                (
                    LaunchBundleLinkResolution::RequiresRuntimeDiscovery,
                    Some(reason.to_string()),
                )
            };
            Ok(LaunchBundleLinkPreview {
                provider_site: link.provider_site.clone(),
                provider_kind: provider.kind,
                provider_component: link.provider_component.clone(),
                provide: link.provide.clone(),
                provider_router_identity_id: provider.router_identity_id.clone(),
                provider_router_mesh_port: provider.router_mesh_port,
                consumer_site: link.consumer_site.clone(),
                consumer_kind: consumer.kind,
                consumer_component: link.consumer_component.clone(),
                slot: link.slot.clone(),
                protocol: link.protocol,
                export_name: link.export_name.clone(),
                external_slot_name: link.external_slot_name.clone(),
                external_slot_env: amber_compiler::mesh::external_slot_env_var(
                    &link.external_slot_name,
                ),
                consumer_mesh_host: container_host_for_consumer(provider.kind, consumer.kind),
                resolution,
                preview_external_url,
                unresolved_reason,
            })
        })
        .collect()
}

fn preview_external_slot_url(
    port: u16,
    peer_key_b64: &str,
    peer_id: &str,
    link: &RunLink,
    provider_kind: SiteKind,
    consumer_kind: SiteKind,
) -> Result<String> {
    let host = container_host_for_consumer(provider_kind, consumer_kind);
    let mut mesh_url = Url::parse(&format!("mesh://{}:{port}", host))
        .into_diagnostic()
        .wrap_err("failed to build preview mesh link url")?;
    mesh_url
        .query_pairs_mut()
        .append_pair("peer_id", peer_id)
        .append_pair("peer_key", peer_key_b64)
        .append_pair(
            "route_id",
            &router_export_route_id(&link.export_name, mesh_protocol(link.protocol)?),
        )
        .append_pair("capability", &link.export_name);
    Ok(mesh_url.to_string())
}

fn site_launch_commands(plan: &SiteSupervisorPlan) -> Result<Vec<LaunchCommandPreview>> {
    let exe = env::current_exe()
        .into_diagnostic()
        .wrap_err("failed to resolve amber executable path")?;
    Ok(match plan.kind {
        SiteKind::Direct => {
            let mut argv = vec![
                exe.display().to_string(),
                "run-direct-init".to_string(),
                "--plan".to_string(),
                PathBuf::from(&plan.artifact_dir)
                    .join("direct-plan.json")
                    .display()
                    .to_string(),
                "--storage-root".to_string(),
                required_path(plan.storage_root.as_deref(), "direct storage root").to_string(),
            ];
            if let Some(runtime_root) = plan.runtime_root.as_deref() {
                argv.push("--runtime-root".to_string());
                argv.push(runtime_root.to_string());
            }
            if let Some(port) = plan.router_mesh_port {
                argv.push("--router-mesh-port".to_string());
                argv.push(port.to_string());
            }
            vec![LaunchCommandPreview {
                argv,
                env: plan.launch_env.clone(),
                current_dir: Some(plan.site_state_root.clone()),
            }]
        }
        SiteKind::Vm => {
            let mut argv = vec![
                exe.display().to_string(),
                "run-vm-init".to_string(),
                "--plan".to_string(),
                PathBuf::from(&plan.artifact_dir)
                    .join("vm-plan.json")
                    .display()
                    .to_string(),
                "--storage-root".to_string(),
                required_path(plan.storage_root.as_deref(), "vm storage root").to_string(),
            ];
            if let Some(runtime_root) = plan.runtime_root.as_deref() {
                argv.push("--runtime-root".to_string());
                argv.push(runtime_root.to_string());
            }
            if let Some(port) = plan.router_mesh_port {
                argv.push("--router-mesh-port".to_string());
                argv.push(port.to_string());
            }
            vec![LaunchCommandPreview {
                argv,
                env: plan.launch_env.clone(),
                current_dir: Some(plan.site_state_root.clone()),
            }]
        }
        SiteKind::Compose => {
            let mut argv = vec![
                "docker".to_string(),
                "compose".to_string(),
                "-f".to_string(),
                PathBuf::from(&plan.artifact_dir)
                    .join("compose.yaml")
                    .display()
                    .to_string(),
            ];
            if let Some(project_name) = plan.compose_project.as_deref() {
                argv.push("-p".to_string());
                argv.push(project_name.to_string());
            }
            argv.push("up".to_string());
            argv.push("-d".to_string());
            vec![LaunchCommandPreview {
                argv,
                env: plan.launch_env.clone(),
                current_dir: Some(plan.artifact_dir.clone()),
            }]
        }
        SiteKind::Kubernetes => {
            let mut commands = Vec::new();
            if let Some(namespace) = plan.kubernetes_namespace.as_deref() {
                let mut get_ns = kubectl_preview(plan.context.as_deref());
                get_ns.extend([
                    "get".to_string(),
                    "namespace".to_string(),
                    namespace.to_string(),
                    "-o".to_string(),
                    "json".to_string(),
                ]);
                commands.push(LaunchCommandPreview {
                    argv: get_ns,
                    env: BTreeMap::new(),
                    current_dir: None,
                });

                let mut create_ns = kubectl_preview(plan.context.as_deref());
                create_ns.extend([
                    "create".to_string(),
                    "namespace".to_string(),
                    namespace.to_string(),
                ]);
                commands.push(LaunchCommandPreview {
                    argv: create_ns,
                    env: BTreeMap::new(),
                    current_dir: None,
                });
            }

            let mut apply = kubectl_preview(plan.context.as_deref());
            apply.extend(["apply".to_string(), "-k".to_string(), ".".to_string()]);
            commands.push(LaunchCommandPreview {
                argv: apply,
                env: BTreeMap::new(),
                current_dir: Some(plan.artifact_dir.clone()),
            });

            if let (Some(namespace), Some(mesh_port), Some(control_port)) = (
                plan.kubernetes_namespace.as_deref(),
                plan.port_forward_mesh_port,
                plan.port_forward_control_port,
            ) {
                let mut port_forward = kubectl_preview(plan.context.as_deref());
                port_forward.extend([
                    "-n".to_string(),
                    namespace.to_string(),
                    "port-forward".to_string(),
                    "--address".to_string(),
                    "0.0.0.0".to_string(),
                    "deploy/amber-router".to_string(),
                    format!("{mesh_port}:24000"),
                    format!("{control_port}:24100"),
                ]);
                commands.push(LaunchCommandPreview {
                    argv: port_forward,
                    env: BTreeMap::new(),
                    current_dir: None,
                });
            }

            commands
        }
    })
}

fn observability_launch_commands(
    observability: &MaterializedObservability,
) -> Result<Vec<LaunchCommandPreview>> {
    let Some(plan_path) = observability.plan_path.as_ref() else {
        return Ok(Vec::new());
    };
    let exe = env::current_exe()
        .into_diagnostic()
        .wrap_err("failed to resolve amber executable path")?;
    Ok(vec![LaunchCommandPreview {
        argv: vec![
            exe.display().to_string(),
            "run-observability-sink".to_string(),
            "--plan".to_string(),
            plan_path.display().to_string(),
        ],
        env: BTreeMap::new(),
        current_dir: Some(
            plan_path
                .parent()
                .and_then(Path::parent)
                .unwrap_or_else(|| Path::new("."))
                .display()
                .to_string(),
        ),
    }])
}

fn kubectl_preview(context: Option<&str>) -> Vec<String> {
    let mut argv = vec!["kubectl".to_string()];
    if let Some(context) = context {
        argv.push("--context".to_string());
        argv.push(context.to_string());
    }
    argv
}

fn materialize_observability(
    run_root: &Path,
    run_id: &str,
    mesh_scope: &str,
    observability: Option<&str>,
) -> Result<Option<MaterializedObservability>> {
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
        return Ok(Some(MaterializedObservability {
            receipt: ObservabilityReceipt {
                endpoint: advertise_endpoint,
                sink_pid: None,
                requests_log: Some(requests_log.display().to_string()),
            },
            plan_path: Some(plan_path),
        }));
    }

    Ok(Some(MaterializedObservability {
        receipt: ObservabilityReceipt {
            endpoint: observability.to_string(),
            sink_pid: None,
            requests_log: None,
        },
        plan_path: None,
    }))
}

async fn start_materialized_observability(
    run_root: &Path,
    observability: Option<&MaterializedObservability>,
) -> Result<Option<ObservabilityReceipt>> {
    let Some(observability) = observability else {
        return Ok(None);
    };
    let Some(plan_path) = observability.plan_path.as_ref() else {
        return Ok(Some(observability.receipt.clone()));
    };

    let mut child = spawn_detached_child(
        run_root,
        &run_root.join("observability").join("sink.log"),
        |cmd| {
            cmd.arg("run-observability-sink")
                .arg("--plan")
                .arg(plan_path);
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
            let mut receipt = observability.receipt.clone();
            receipt.sink_pid = Some(child.id());
            return Ok(Some(receipt));
        }
        sleep(Duration::from_millis(100)).await;
    }
    Err(miette::miette!("timed out waiting for observability sink"))
}

fn prepare_site_launch(
    site: &MaterializedSite,
    runtime_env: &BTreeMap<String, String>,
    external_env: &BTreeMap<String, String>,
) -> Result<()> {
    let artifact_env = merge_env_maps(runtime_env, external_env);
    patch_site_artifacts(
        &site.artifact_dir,
        site.site_plan.site.kind,
        &artifact_env,
        site.base_supervisor_plan.observability_endpoint.as_deref(),
    )?;
    let mut supervisor_plan = site.base_supervisor_plan.clone();
    supervisor_plan.launch_env.extend(
        external_env
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    write_json(
        &site_supervisor_plan_path(&site.site_state_root),
        &supervisor_plan,
    )?;
    write_json(
        &desired_links_path(&site.site_state_root),
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
    )
}

pub(crate) async fn run_run_plan(
    source_plan_path: Option<&Path>,
    run_plan: &RunPlan,
    storage_root_override: Option<&Path>,
    observability: Option<&str>,
    site_launch_env: &BTreeMap<String, String>,
) -> Result<RunReceipt> {
    let run_id = new_run_id();
    run_run_plan_with_id(
        source_plan_path,
        run_plan,
        storage_root_override,
        observability,
        &run_id,
        site_launch_env,
    )
    .await
}

pub(crate) async fn run_run_plan_with_id(
    source_plan_path: Option<&Path>,
    run_plan: &RunPlan,
    storage_root_override: Option<&Path>,
    observability: Option<&str>,
    run_id: &str,
    site_launch_env: &BTreeMap<String, String>,
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

    let launch_bundle = materialize_launch_bundle(
        source_plan_path,
        run_plan,
        &run_root,
        run_id,
        observability,
        site_launch_env,
    )?;
    let observability_receipt =
        start_materialized_observability(&run_root, launch_bundle.observability.as_ref()).await?;
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
    let mut bridge_proxies = BTreeMap::<BridgeProxyKey, BridgeProxyHandle>::new();
    let test_wave_delay = test_wave_delay()?;

    let result = async {
        for wave in &run_plan.startup_waves {
            for site_id in wave {
                let site = launch_bundle
                    .sites
                    .get(site_id)
                    .ok_or_else(|| miette::miette!("launch bundle is missing site `{site_id}`"))?;
                let external_env = external_slot_env_for_site(
                    site_id,
                    site.site_plan.site.kind,
                    &run_plan.links,
                    &launched_by_site,
                )?;
                prepare_site_launch(site, site_launch_env, &external_env)?;

                let mut supervisor = spawn_site_supervisor(&site.site_state_root)?;
                let launched = wait_for_site_ready(
                    site_id,
                    &site.site_plan,
                    &site.site_state_root,
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
                    &run_root,
                    &state_root,
                    &mut bridge_proxies,
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
            if let Some(delay) = test_wave_delay {
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
            plan_path: launch_bundle.run_plan_path.display().to_string(),
            source_plan_path: source_plan_path.map(|path| path.display().to_string()),
            run_root: run_root.display().to_string(),
            observability: observability_receipt.clone(),
            bridge_proxies: bridge_proxies
                .values()
                .map(|proxy| BridgeProxyReceipt {
                    export_name: proxy.export_name.clone(),
                    pid: proxy.child.id(),
                    listen: proxy.listen.to_string(),
                })
                .collect(),
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
        for bridge in bridge_proxies.values_mut() {
            send_sigterm(bridge.child.id());
        }
        for supervisor in supervisor_children.values_mut() {
            send_sigterm(supervisor.child.id());
        }
        for bridge in bridge_proxies.values_mut() {
            let _ = wait_for_child_exit(&mut bridge.child, PROCESS_SHUTDOWN_GRACE_PERIOD).await;
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
            let _ = stop_site_from_receipt(&run_root, site_id, receipt).await;
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
    let supervisor_stop_timeout = site_supervisor_stop_timeout();
    let forced_supervisor_exit_grace_period = forced_supervisor_exit_grace_period();
    write_stop_marker(&run_root)?;
    for site in receipt.sites.values() {
        send_sigterm(site.supervisor_pid);
    }

    let mut shutdown_failures = Vec::new();
    for (site_id, site) in &receipt.sites {
        let state_path = site_state_path(&run_root.join("state"), site_id);
        write_site_state(
            &state_path,
            site_state_from_receipt(&receipt, site_id, site, SiteLifecycleStatus::Stopping, None),
        )?;
        match wait_for_site_supervisor_stop(
            &state_path,
            site.supervisor_pid,
            supervisor_stop_timeout,
        )
        .await?
        {
            SiteSupervisorStopStatus::Graceful { shutdown_failed } => {
                if shutdown_failed {
                    finalize_site_stop_via_orphan_cleanup(
                        &run_root,
                        &state_path,
                        &receipt,
                        site_id,
                        site,
                        format!(
                            "site supervisor `{site_id}` reported failed shutdown; orphan cleanup \
                             completed"
                        ),
                    )
                    .await?;
                }
            }
            SiteSupervisorStopStatus::Exited => {
                finalize_site_stop_via_orphan_cleanup(
                    &run_root,
                    &state_path,
                    &receipt,
                    site_id,
                    site,
                    format!(
                        "site supervisor `{site_id}` exited before confirming stop; orphan \
                         cleanup completed"
                    ),
                )
                .await?;
            }
            SiteSupervisorStopStatus::TimedOut => {
                let message = format!(
                    "site supervisor `{site_id}` (pid {}) did not stop within {}s; forcing \
                     shutdown",
                    site.supervisor_pid,
                    supervisor_stop_timeout.as_secs()
                );
                #[cfg(unix)]
                send_sigkill(site.supervisor_pid);
                #[cfg(not(unix))]
                send_sigterm(site.supervisor_pid);

                if !wait_for_pid_exit(site.supervisor_pid, forced_supervisor_exit_grace_period)
                    .await
                {
                    shutdown_failures.push(format!(
                        "site supervisor `{site_id}` (pid {}) did not exit after forced shutdown",
                        site.supervisor_pid
                    ));
                    continue;
                }

                finalize_site_stop_via_orphan_cleanup(
                    &run_root,
                    &state_path,
                    &receipt,
                    site_id,
                    site,
                    message,
                )
                .await?;
            }
        }
    }

    if let Some(observability) = receipt.observability.as_ref()
        && let Some(pid) = observability.sink_pid
    {
        send_sigterm(pid);
    }

    if let Some(observability) = receipt.observability.as_ref()
        && let Some(pid) = observability.sink_pid
        && !wait_for_pid_exit(pid, PROCESS_SHUTDOWN_GRACE_PERIOD).await
    {
        shutdown_failures.push(format!(
            "observability sink (pid {pid}) did not stop within {}s",
            PROCESS_SHUTDOWN_GRACE_PERIOD.as_secs()
        ));
    }
    for proxy in &receipt.bridge_proxies {
        send_sigterm(proxy.pid);
    }
    for proxy in &receipt.bridge_proxies {
        if !wait_for_pid_exit(proxy.pid, PROCESS_SHUTDOWN_GRACE_PERIOD).await {
            shutdown_failures.push(format!(
                "bridge proxy `{}` (pid {}) did not stop within {}s",
                proxy.export_name,
                proxy.pid,
                PROCESS_SHUTDOWN_GRACE_PERIOD.as_secs()
            ));
        }
    }

    if !shutdown_failures.is_empty() {
        return Err(miette::miette!(
            "mixed run `{run_id}` did not stop completely:\n{}",
            shutdown_failures.join("\n")
        ));
    }

    let _ = fs::remove_file(receipt_path(&run_root));
    Ok(())
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
        control_allow: None,
        peers: peers.into_values().collect(),
        inbound,
        outbound,
        transport: TransportConfig::NoiseIk {},
    };

    let router = tokio::spawn(async move { amber_router::run(config).await });
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

async fn stop_site_from_receipt(run_root: &Path, site_id: &str, site: &SiteReceipt) -> Result<()> {
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

fn resolve_proxy_run_root(
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

fn select_proxy_site<'a>(
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

fn build_run_outside_proxy_context(
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

fn proxy_metadata_view(site_plan: &RunSitePlan) -> Result<ProxyMetadata> {
    load_site_proxy_metadata(site_plan)
}

fn build_outside_proxy_identity(run_id: &str, mesh_scope: &str) -> MeshIdentity {
    let mut identity = MeshIdentity::generate("outside", Some(mesh_scope.to_string()));
    let suffix = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&identity.public_key[..6]);
    identity.id = format!("/run/{run_id}/outside/{suffix}");
    identity
}

fn mesh_protocol_for_capability(kind: CapabilityKind) -> Result<MeshProtocol> {
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

fn mesh_protocol_for_export(protocol: &str) -> Result<MeshProtocol> {
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

fn outside_slot_mesh_url(
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

fn outside_proxy_mesh_listen_addr(
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

async fn wait_for_socket_listener(addr: SocketAddr) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if router_mesh_listener_ready(addr).await {
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }
    Err(miette::miette!("timed out waiting for listener {}", addr))
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
    launch_env: &BTreeMap<String, String>,
    observability_endpoint: Option<&str>,
) -> Result<()> {
    if matches!(kind, SiteKind::Kubernetes) {
        for env_file_name in [
            DEFAULT_EXTERNAL_ENV_FILE,
            "root-config.env",
            "root-config-secret.env",
        ] {
            let env_file = artifact_dir.join(env_file_name);
            if env_file.is_file() {
                patch_generated_env_file(&env_file, launch_env)?;
            }
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

fn patch_generated_env_file(path: &Path, launch_env: &BTreeMap<String, String>) -> Result<()> {
    let raw = fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", path.display()))?;
    let mut out = String::new();
    for line in raw.lines() {
        if let Some((key, _)) = line.split_once('=')
            && let Some(value) = launch_env.get(key.trim())
        {
            out.push_str(key.trim());
            out.push('=');
            out.push_str(value);
            out.push('\n');
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    fs::write(path, out)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", path.display()))
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
        let Some(provider) = launched_by_site.get(&link.provider_site) else {
            if link.weak {
                continue;
            }
            return Err(miette::miette!(
                "provider site `{}` has not been launched before consumer site `{site_id}`",
                link.provider_site
            ));
        };
        env.insert(
            amber_compiler::mesh::external_slot_env_var(&link.external_slot_name),
            external_slot_url(provider, link, consumer_kind)?,
        );
    }
    Ok(env)
}

fn external_slot_name_from_env_var(env_var: &str) -> String {
    let slot = env_var
        .strip_prefix("AMBER_EXTERNAL_SLOT_")
        .unwrap_or(env_var);
    slot.strip_suffix("_URL")
        .unwrap_or(slot)
        .to_ascii_lowercase()
}

fn launch_env(
    run_id: &str,
    mesh_scope: &str,
    kind: SiteKind,
    runtime_env: &BTreeMap<String, String>,
    external_env: &BTreeMap<String, String>,
    observability_endpoint: Option<&str>,
) -> Result<BTreeMap<String, String>> {
    let mut env = merge_env_maps(runtime_env, external_env);
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

fn merge_env_maps(
    left: &BTreeMap<String, String>,
    right: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut merged = left.clone();
    merged.extend(right.clone());
    merged
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
            .then(|| {
                prepare_kubernetes_artifact_namespace(
                    input.run_id,
                    input.site_id,
                    input.artifact_dir,
                )
            })
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
    let deadline = Instant::now() + site_ready_timeout(site_plan);
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

fn site_ready_timeout(site_plan: &RunSitePlan) -> Duration {
    if matches!(site_plan.site.kind, SiteKind::Vm) && vm_uses_tcg_accel() {
        TCG_VM_STARTUP_TIMEOUT
    } else {
        site_ready_timeout_for_kind(site_plan.site.kind)
    }
}

fn site_ready_timeout_for_kind(kind: SiteKind) -> Duration {
    match kind {
        SiteKind::Kubernetes => KUBERNETES_WORKLOAD_READY_TIMEOUT + KUBERNETES_SITE_READY_BUFFER,
        SiteKind::Direct | SiteKind::Compose | SiteKind::Vm => Duration::from_secs(120),
    }
}

async fn register_new_site_links(
    site_id: &str,
    links: &[RunLink],
    launched: &mut LaunchedSite,
    launched_by_site: &BTreeMap<String, LaunchedSite>,
    run_root: &Path,
    state_root: &Path,
    bridge_proxies: &mut BTreeMap<BridgeProxyKey, BridgeProxyHandle>,
) -> Result<()> {
    for link in links {
        if link.consumer_site == site_id {
            let Some(provider) = launched_by_site.get(&link.provider_site) else {
                if link.weak {
                    continue;
                }
                return Err(miette::miette!(
                    "provider site `{}` is not active",
                    link.provider_site
                ));
            };
            let external_url = resolve_link_external_url(
                provider,
                link,
                launched.receipt.kind,
                run_root,
                bridge_proxies,
            )
            .await?;
            let consumer_key = base64::engine::general_purpose::STANDARD
                .encode(launched.router_identity.public_key);

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
            continue;
        }
        if link.provider_site != site_id {
            continue;
        }
        let Some(consumer) = launched_by_site.get(&link.consumer_site) else {
            continue;
        };
        let external_url = resolve_link_external_url(
            launched,
            link,
            consumer.receipt.kind,
            run_root,
            bridge_proxies,
        )
        .await?;
        let consumer_key =
            base64::engine::general_purpose::STANDARD.encode(consumer.router_identity.public_key);

        register_external_slot_with_retry(
            &consumer.router_control,
            &link.external_slot_name,
            &external_url,
            ROUTER_CONTROL_TIMEOUT,
        )
        .await?;
        register_export_peer_with_retry(
            &launched.router_control,
            &link.export_name,
            &consumer.router_identity.id,
            &consumer_key,
            &link.protocol.to_string(),
            ROUTER_CONTROL_TIMEOUT,
        )
        .await?;

        update_desired_links_for_consumer(
            &state_root.join(&link.consumer_site),
            &link.external_slot_name,
            &external_url,
        )?;
        update_desired_links_for_provider(
            &state_root.join(site_id),
            DesiredExportPeer {
                export_name: link.export_name.clone(),
                peer_id: consumer.router_identity.id.clone(),
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

fn launched_site_from_receipt(
    site_receipt: &SiteReceipt,
    mesh_scope: &str,
) -> Result<LaunchedSite> {
    let router_control = parse_control_endpoint(
        site_receipt
            .router_control
            .as_deref()
            .ok_or_else(|| miette::miette!("site receipt is missing router control"))?,
    )?;
    let router_addr = site_receipt
        .router_mesh_addr
        .as_deref()
        .ok_or_else(|| miette::miette!("site receipt is missing router mesh addr"))?
        .parse()
        .into_diagnostic()
        .wrap_err("invalid router mesh addr in site receipt")?;
    let router_identity = MeshIdentityPublic {
        id: site_receipt
            .router_identity_id
            .clone()
            .ok_or_else(|| miette::miette!("site receipt is missing router identity id"))?,
        public_key: decode_public_key(
            site_receipt
                .router_public_key_b64
                .as_deref()
                .ok_or_else(|| miette::miette!("site receipt is missing router public key"))?,
        )?,
        mesh_scope: Some(mesh_scope.to_string()),
    };
    Ok(LaunchedSite {
        receipt: site_receipt.clone(),
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
                runtime.ready_since = None;
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
                runtime.ready_since = None;
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
                runtime.ready_since = None;
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
                runtime.ready_since = None;
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
                ensure_kubernetes_workloads_ready(plan)?;
                runtime.site_started = true;
            }
            if runtime.port_forward.is_none() {
                runtime.ready_since = None;
                runtime.port_forward = Some(spawn_port_forward(plan)?);
            }
        }
    }
    Ok(())
}

async fn try_discover_site(
    plan: &SiteSupervisorPlan,
    runtime: &mut SupervisorRuntime,
    stop_requested: &AtomicBool,
    run_root: &Path,
) -> Result<Option<RouterDiscovery>> {
    reap_child(&mut runtime.site_process)?;
    reap_child(&mut runtime.port_forward)?;
    let discovery = match plan.kind {
        SiteKind::Direct => try_discover_direct_site(plan, runtime, stop_requested, run_root).await,
        SiteKind::Vm => try_discover_vm_site(plan, runtime, stop_requested, run_root).await,
        SiteKind::Compose => try_discover_compose_site(plan, stop_requested, run_root).await,
        SiteKind::Kubernetes => {
            try_discover_kubernetes_site(plan, runtime, stop_requested, run_root).await
        }
    }?;
    if discovery.is_none() && plan.kind == SiteKind::Compose {
        runtime.site_started = false;
    }
    Ok(discovery)
}

async fn try_discover_direct_site(
    plan: &SiteSupervisorPlan,
    runtime: &SupervisorRuntime,
    stop_requested: &AtomicBool,
    run_root: &Path,
) -> Result<Option<RouterDiscovery>> {
    let Some(_site_process) = runtime.site_process.as_ref() else {
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
        let router_identity = match run_until_stop(
            run_root,
            stop_requested,
            fetch_router_identity(&control_endpoint),
        )
        .await
        {
            Ok(Some(router_identity)) => router_identity,
            Ok(None) | Err(_) => return Ok(None),
        };
        let router_addr = SocketAddr::from(([127, 0, 0, 1], router_mesh_port));
        return Ok(Some(RouterDiscovery {
            control_endpoint,
            router_identity,
            router_addr: Some(router_addr),
        }));
    }
    Ok(None)
}

async fn try_discover_vm_site(
    plan: &SiteSupervisorPlan,
    runtime: &SupervisorRuntime,
    stop_requested: &AtomicBool,
    run_root: &Path,
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
    let router_identity = match run_until_stop(
        run_root,
        stop_requested,
        fetch_router_identity(&control_endpoint),
    )
    .await
    {
        Ok(Some(router_identity)) => router_identity,
        Ok(None) | Err(_) => return Ok(None),
    };
    let router_addr = SocketAddr::from(([127, 0, 0, 1], router_mesh_port));
    if !vm_component_targets_ready(plan, &artifact_dir)? {
        return Ok(None);
    }
    Ok(Some(RouterDiscovery {
        control_endpoint,
        router_identity,
        router_addr: Some(router_addr),
    }))
}

fn vm_component_targets_ready(plan: &SiteSupervisorPlan, artifact_dir: &Path) -> Result<bool> {
    let runtime_root = Path::new(required_str(
        plan.runtime_root.as_deref(),
        "vm runtime root",
    )?);
    if !runtime_root.is_dir() {
        return Ok(false);
    }

    let vm_plan: VmPlan = read_json(&artifact_dir.join(VM_PLAN_FILENAME), "vm plan")?;
    for component in &vm_plan.components {
        if !mesh_config_local_targets_ready(
            &runtime_root.join(&component.mesh_config_path),
            VM_LOCAL_TARGET_READY_TIMEOUT,
        )? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn mesh_config_local_targets_ready(path: &Path, timeout: Duration) -> Result<bool> {
    if !path.is_file() {
        return Ok(false);
    }

    let config: MeshConfigPublic = read_json(path, "mesh config")?;
    for route in config.inbound {
        let InboundTarget::Local { port } = route.target else {
            continue;
        };
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let ready = match route.protocol {
            MeshProtocol::Http => wait_for_http_response(addr, timeout).is_ok(),
            MeshProtocol::Tcp => wait_for_stable_endpoint(addr, timeout).is_ok(),
        };
        if !ready {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn try_discover_compose_site(
    plan: &SiteSupervisorPlan,
    stop_requested: &AtomicBool,
    run_root: &Path,
) -> Result<Option<RouterDiscovery>> {
    run_until_stop(
        run_root,
        stop_requested,
        discover_router_for_output(&plan.artifact_dir, plan.compose_project.as_deref(), true),
    )
    .await
    .wrap_err_with(|| format!("compose router discovery for site `{}`", plan.site_id))
}

async fn try_discover_kubernetes_site(
    plan: &SiteSupervisorPlan,
    runtime: &mut SupervisorRuntime,
    stop_requested: &AtomicBool,
    run_root: &Path,
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
    let router_identity = match run_until_stop(
        run_root,
        stop_requested,
        fetch_router_identity(&control_endpoint),
    )
    .await
    {
        Ok(Some(router_identity)) => router_identity,
        Ok(None) | Err(_) => return Ok(None),
    };
    let router_addr = SocketAddr::from(([127, 0, 0, 1], mesh_port));
    if !router_mesh_listener_ready(router_addr).await {
        return Ok(None);
    }
    Ok(Some(RouterDiscovery {
        control_endpoint,
        router_identity,
        router_addr: Some(router_addr),
    }))
}

async fn apply_desired_links(
    plan: &SiteSupervisorPlan,
    endpoint: &ControlEndpoint,
    stop_requested: &AtomicBool,
    run_root: &Path,
) -> Result<bool> {
    let desired: DesiredLinkState = read_json(
        &desired_links_path(Path::new(&plan.site_state_root)),
        "desired links",
    )?;
    for (env_var, url) in &desired.external_slots {
        let slot = external_slot_name_from_env_var(env_var);
        if run_until_stop(
            run_root,
            stop_requested,
            register_external_slot_with_retry(endpoint, &slot, url, Duration::from_secs(2)),
        )
        .await?
        .is_none()
        {
            return Ok(false);
        }
    }
    for peer in &desired.export_peers {
        if run_until_stop(
            run_root,
            stop_requested,
            register_export_peer_with_retry(
                endpoint,
                &peer.export_name,
                &peer.peer_id,
                &peer.peer_key_b64,
                &peer.protocol,
                Duration::from_secs(2),
            ),
        )
        .await?
        .is_none()
        {
            return Ok(false);
        }
    }
    Ok(true)
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
                    .envs(plan.launch_env.clone())
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

fn read_compose_launch_env(run_root: &Path, site_id: &str) -> Result<BTreeMap<String, String>> {
    let plan_path = site_supervisor_plan_path(&run_root.join("state").join(site_id));
    if !plan_path.is_file() {
        return Ok(BTreeMap::new());
    }
    let plan: SiteSupervisorPlan = read_json(&plan_path, "site supervisor plan")?;
    Ok(plan.launch_env)
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
    let context = plan.context.as_deref();
    let mut last_error = None::<String>;
    loop {
        let output = kubectl_command(context)
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
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if stderr.contains("context") && stderr.contains("does not exist") {
                let context = context.unwrap_or("<current>");
                return Err(miette::miette!(
                    "kubernetes context `{context}` is not available: {stderr}"
                ));
            }
            if stderr.contains("(NotFound)") || stderr.contains("not found") {
                let create_output = kubectl_command(context)
                    .arg("create")
                    .arg("namespace")
                    .arg(namespace)
                    .output()
                    .into_diagnostic()
                    .wrap_err_with(|| {
                        format!("failed to create kubernetes namespace `{namespace}`")
                    })?;
                if create_output.status.success() {
                    return Ok(());
                }
                last_error = Some(
                    String::from_utf8_lossy(&create_output.stderr)
                        .trim()
                        .to_string(),
                );
            } else if !stderr.is_empty() {
                last_error = Some(stderr);
            }
        }
        if Instant::now() >= deadline {
            let detail = last_error
                .as_deref()
                .filter(|detail| !detail.is_empty())
                .map(|detail| format!(": {detail}"))
                .unwrap_or_default();
            return Err(miette::miette!(
                "failed to prepare kubernetes namespace `{namespace}` within {}s{detail}",
                KUBERNETES_NAMESPACE_READY_TIMEOUT.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn ensure_kubernetes_workloads_ready(plan: &SiteSupervisorPlan) -> Result<()> {
    let namespace = required_str(plan.kubernetes_namespace.as_deref(), "kubernetes namespace")?;
    let context = plan.context.as_deref();
    let timeout = format!("{}s", KUBERNETES_WORKLOAD_READY_TIMEOUT.as_secs());
    let checks = [
        (
            "wait for kubernetes jobs",
            vec![
                "-n",
                namespace,
                "wait",
                "--for=condition=complete",
                "--timeout",
                timeout.as_str(),
                "job",
                "--all",
            ],
        ),
        (
            "wait for kubernetes deployments",
            vec![
                "-n",
                namespace,
                "wait",
                "--for=condition=available",
                "--timeout",
                timeout.as_str(),
                "deployment",
                "--all",
            ],
        ),
    ];

    for (label, args) in checks {
        let output = kubectl_command(context)
            .args(args)
            .output()
            .into_diagnostic()
            .wrap_err_with(|| format!("{label} for site `{}`", plan.site_id))?;
        if output.status.success() {
            continue;
        }
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let detail = if stderr.is_empty() {
            format!("status {}", output.status)
        } else {
            stderr
        };
        return Err(miette::miette!(
            "{label} for site `{}` failed: {detail}",
            plan.site_id
        ));
    }

    Ok(())
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
    #[cfg(unix)]
    {
        terminate_recorded_processes(&[child.id()]).await?;
        let _ = child.wait();
        Ok(())
    }

    #[cfg(not(unix))]
    {
        send_sigterm(child.id());
        let _ = wait_for_child_exit(child, PROCESS_SHUTDOWN_GRACE_PERIOD).await;
        Ok(())
    }
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

async fn wait_for_pid_exit(pid: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if !pid_is_alive(pid) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        sleep(Duration::from_millis(100)).await;
    }
}

async fn resolve_link_external_url(
    provider: &LaunchedSite,
    link: &RunLink,
    consumer_kind: SiteKind,
    run_root: &Path,
    bridge_proxies: &mut BTreeMap<BridgeProxyKey, BridgeProxyHandle>,
) -> Result<String> {
    if !link_needs_bridge_proxy(provider.receipt.kind, consumer_kind) {
        return external_slot_url(provider, link, consumer_kind);
    }

    let port = ensure_bridge_proxy(
        run_root,
        provider,
        &link.export_name,
        consumer_kind,
        bridge_proxies,
    )
    .await?;
    bridge_proxy_external_url(port, link.protocol, consumer_kind)
}

fn link_needs_bridge_proxy(_provider_kind: SiteKind, consumer_kind: SiteKind) -> bool {
    matches!(consumer_kind, SiteKind::Compose | SiteKind::Kubernetes)
}

async fn ensure_bridge_proxy(
    run_root: &Path,
    provider: &LaunchedSite,
    export_name: &str,
    consumer_kind: SiteKind,
    bridge_proxies: &mut BTreeMap<BridgeProxyKey, BridgeProxyHandle>,
) -> Result<u16> {
    let key = BridgeProxyKey {
        export_name: export_name.to_string(),
        consumer_kind,
    };
    if let Some(proxy) = bridge_proxies.get_mut(&key)
        && proxy.child.try_wait().into_diagnostic()?.is_none()
    {
        return Ok(proxy.listen.port());
    }

    let listen = bridge_proxy_bind_addr(consumer_kind, reserve_loopback_port()?);
    let child = spawn_bridge_proxy(run_root, provider, export_name, listen)?;
    wait_for_socket_listener(bridge_proxy_probe_addr(listen)).await?;
    bridge_proxies.insert(
        key,
        BridgeProxyHandle {
            child,
            export_name: export_name.to_string(),
            listen,
        },
    );
    Ok(listen.port())
}

fn spawn_bridge_proxy(
    run_root: &Path,
    provider: &LaunchedSite,
    export_name: &str,
    listen: SocketAddr,
) -> Result<Child> {
    let logs_root = run_root.join("bridge-proxies");
    fs::create_dir_all(&logs_root)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create {}", logs_root.display()))?;
    let log_path = logs_root.join(format!("{export_name}.log"));
    spawn_detached_child(run_root, &log_path, |cmd| {
        cmd.arg("proxy")
            .arg(&provider.receipt.artifact_dir)
            .arg("--export")
            .arg(bridge_proxy_export_binding(export_name, listen));
        if provider.receipt.kind == SiteKind::Kubernetes {
            let control = provider.router_control.to_string();
            cmd.arg("--router-addr")
                .arg(provider.router_addr.to_string())
                .arg("--router-control-addr")
                .arg(control);
        }
    })
}

fn bridge_proxy_export_binding(export_name: &str, listen: SocketAddr) -> String {
    format!("{export_name}={}:{}", listen.ip(), listen.port())
}

fn bridge_proxy_bind_addr(consumer_kind: SiteKind, port: u16) -> SocketAddr {
    host_proxy_bind_addr(consumer_needs_host_wide_listener(consumer_kind), port)
}

fn bridge_proxy_probe_addr(listen: SocketAddr) -> SocketAddr {
    listener_probe_addr(listen)
}

fn bridge_proxy_external_url(
    port: u16,
    protocol: NetworkProtocol,
    consumer_kind: SiteKind,
) -> Result<String> {
    let host = bridge_proxy_host_for_consumer(consumer_kind);
    Ok(match protocol {
        NetworkProtocol::Http | NetworkProtocol::Https => format!("http://{host}:{port}"),
        NetworkProtocol::Tcp => format!("tcp://{host}:{port}"),
        _ => {
            return Err(miette::miette!(
                "mixed-site bridge proxy does not support protocol `{protocol}`"
            ));
        }
    })
}

fn bridge_proxy_host_for_consumer(consumer_kind: SiteKind) -> String {
    match consumer_kind {
        SiteKind::Compose => CONTAINER_HOST_ALIAS.to_string(),
        SiteKind::Direct | SiteKind::Vm | SiteKind::Kubernetes => {
            container_host_for_consumer(SiteKind::Direct, consumer_kind)
        }
    }
}

fn consumer_needs_host_wide_listener(consumer_kind: SiteKind) -> bool {
    matches!(consumer_kind, SiteKind::Compose | SiteKind::Kubernetes)
}

fn host_proxy_bind_addr(needs_host_wide_listener: bool, port: u16) -> SocketAddr {
    if needs_host_wide_listener {
        SocketAddr::from(([0, 0, 0, 0], port))
    } else {
        SocketAddr::from(([127, 0, 0, 1], port))
    }
}

fn listener_probe_addr(listen: SocketAddr) -> SocketAddr {
    if listen.ip().is_unspecified() {
        SocketAddr::from(([127, 0, 0, 1], listen.port()))
    } else {
        listen
    }
}

fn external_slot_url(
    provider: &LaunchedSite,
    link: &RunLink,
    consumer_kind: SiteKind,
) -> Result<String> {
    let host = container_host_for_consumer(provider.receipt.kind, consumer_kind);
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

fn container_host_for_consumer(provider_kind: SiteKind, consumer_kind: SiteKind) -> String {
    let container_host_ip = container_host_ip();
    container_host_from_resolved_ip(provider_kind, consumer_kind, container_host_ip.as_deref())
}

fn container_host_from_resolved_ip(
    provider_kind: SiteKind,
    consumer_kind: SiteKind,
    container_host_ip: Option<&str>,
) -> String {
    match consumer_kind {
        SiteKind::Direct | SiteKind::Vm => "127.0.0.1".to_string(),
        SiteKind::Compose => {
            if provider_kind == SiteKind::Kubernetes {
                container_host_ip
                    .unwrap_or(CONTAINER_HOST_ALIAS)
                    .to_string()
            } else {
                CONTAINER_HOST_ALIAS.to_string()
            }
        }
        SiteKind::Kubernetes => container_host_ip
            .unwrap_or(CONTAINER_HOST_ALIAS)
            .to_string(),
    }
}

fn container_host_ip() -> Option<String> {
    KUBERNETES_CONTAINER_HOST_IP
        .get_or_init(resolve_container_host_ip)
        .clone()
}

fn resolve_container_host_ip() -> Option<String> {
    if cfg!(target_os = "linux") {
        return resolve_linux_container_host_ip();
    }
    resolve_desktop_container_host_ip()
}

fn resolve_linux_container_host_ip() -> Option<String> {
    let output = Command::new("docker")
        .arg("network")
        .arg("inspect")
        .arg("bridge")
        .arg("--format")
        .arg("{{(index .IPAM.Config 0).Gateway}}")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let host = String::from_utf8(output.stdout).ok()?.trim().to_string();
    host.parse::<std::net::IpAddr>().ok()?;
    Some(host)
}

fn resolve_desktop_container_host_ip() -> Option<String> {
    let output = Command::new("docker")
        .arg("run")
        .arg("--rm")
        .arg("busybox:1.36.1")
        .arg("nslookup")
        .arg(CONTAINER_HOST_ALIAS)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    String::from_utf8(output.stdout)
        .ok()?
        .lines()
        .flat_map(str::split_whitespace)
        .filter_map(|token| token.parse::<std::net::Ipv4Addr>().ok())
        .map(|ip| ip.to_string())
        .next_back()
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
mod tests {
    use std::collections::BTreeMap;

    use tempfile::tempdir;

    use super::*;

    fn test_site_receipt(
        kind: SiteKind,
        artifact_dir: &Path,
        router_control: Option<&str>,
        router_mesh_addr: Option<&str>,
    ) -> SiteReceipt {
        SiteReceipt {
            kind,
            artifact_dir: artifact_dir.display().to_string(),
            supervisor_pid: 100,
            process_pid: None,
            compose_project: None,
            kubernetes_namespace: None,
            port_forward_pid: None,
            context: None,
            router_control: router_control.map(str::to_string),
            router_mesh_addr: router_mesh_addr.map(str::to_string),
            router_identity_id: None,
            router_public_key_b64: None,
        }
    }

    fn test_site_state(
        run_id: &str,
        site_id: &str,
        kind: SiteKind,
        artifact_dir: &Path,
        router_control: Option<&str>,
        router_mesh_addr: Option<&str>,
    ) -> SiteManagerState {
        SiteManagerState {
            schema: "amber.run.site-state".to_string(),
            version: 1,
            run_id: run_id.to_string(),
            site_id: site_id.to_string(),
            kind,
            status: SiteLifecycleStatus::Running,
            artifact_dir: artifact_dir.display().to_string(),
            supervisor_pid: 101,
            process_pid: None,
            compose_project: None,
            kubernetes_namespace: None,
            port_forward_pid: None,
            context: None,
            router_control: router_control.map(str::to_string),
            router_mesh_addr: router_mesh_addr.map(str::to_string),
            router_identity_id: None,
            router_public_key_b64: None,
            last_error: None,
        }
    }

    #[test]
    fn forwarded_endpoint_ready_accepts_open_connection() {
        let listener =
            TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr");
        let handle = std::thread::spawn(move || {
            let (_stream, _) = listener.accept().expect("listener should accept");
            std::thread::sleep(Duration::from_millis(500));
        });

        assert!(crate::tcp_readiness::endpoint_accepts_stable_connection(
            addr,
            Duration::from_millis(250),
            Duration::from_millis(250),
        ));
        handle.join().expect("listener thread should finish");
    }

    #[test]
    fn forwarded_endpoint_ready_rejects_reset_connection() {
        let listener =
            TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr");
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("listener should accept");
            drop(stream);
        });

        assert!(!crate::tcp_readiness::endpoint_accepts_stable_connection(
            addr,
            Duration::from_millis(250),
            Duration::from_millis(250),
        ));
        handle.join().expect("listener thread should finish");
    }

    fn test_local_mesh_config(path: &Path, protocol: MeshProtocol, port: u16) -> Result<()> {
        write_json(
            path,
            &MeshConfigPublic {
                identity: MeshIdentityPublic {
                    id: "/site/test/router".to_string(),
                    public_key: [7; 32],
                    mesh_scope: Some("test-scope".to_string()),
                },
                mesh_listen: SocketAddr::from(([127, 0, 0, 1], 24000)),
                control_listen: Some(SocketAddr::from(([127, 0, 0, 1], 24100))),
                control_allow: None,
                peers: Vec::new(),
                inbound: vec![InboundRoute {
                    route_id: "route".to_string(),
                    capability: "http".to_string(),
                    capability_kind: None,
                    capability_profile: None,
                    protocol,
                    http_plugins: Vec::new(),
                    target: InboundTarget::Local { port },
                    allowed_issuers: Vec::new(),
                }],
                outbound: Vec::new(),
                transport: TransportConfig::NoiseIk {},
            },
        )
    }

    #[test]
    fn mesh_config_local_targets_ready_accepts_http_inbound_routes() {
        let temp = tempdir().expect("tempdir should be created");
        let config_path = temp.path().join("mesh-config.json");
        let listener =
            TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr");
        test_local_mesh_config(&config_path, MeshProtocol::Http, addr.port())
            .expect("mesh config should be written");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("listener should accept");
            let mut request = [0u8; 256];
            let _ = stream.read(&mut request);
            let _ = stream.write_all(
                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        });

        assert!(
            mesh_config_local_targets_ready(&config_path, Duration::from_secs(1))
                .expect("mesh config should be readable")
        );
        handle.join().expect("listener thread should finish");
    }

    #[test]
    fn mesh_config_local_targets_ready_rejects_unreachable_http_inbound_routes() {
        let temp = tempdir().expect("tempdir should be created");
        let config_path = temp.path().join("mesh-config.json");
        let listener =
            TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr");
        drop(listener);
        test_local_mesh_config(&config_path, MeshProtocol::Http, addr.port())
            .expect("mesh config should be written");

        assert!(
            !mesh_config_local_targets_ready(&config_path, Duration::from_millis(100))
                .expect("mesh config should be readable")
        );
    }

    #[test]
    fn read_compose_launch_env_returns_saved_launch_env() {
        let temp = tempdir().expect("tempdir should be created");
        let run_root = temp.path().join("run-root");
        let state_root = run_root.join("state").join("compose_local");
        write_json(
            &site_supervisor_plan_path(&state_root),
            &SiteSupervisorPlan {
                schema: SITE_PLAN_SCHEMA.to_string(),
                version: SITE_PLAN_VERSION,
                run_id: "run-123".to_string(),
                mesh_scope: "test.scope".to_string(),
                run_root: run_root.display().to_string(),
                coordinator_pid: 1,
                site_id: "compose_local".to_string(),
                kind: SiteKind::Compose,
                artifact_dir: temp.path().join("artifact").display().to_string(),
                site_state_root: state_root.display().to_string(),
                storage_root: None,
                runtime_root: None,
                router_mesh_port: None,
                compose_project: Some("amber-test".to_string()),
                kubernetes_namespace: None,
                context: None,
                port_forward_mesh_port: None,
                port_forward_control_port: None,
                observability_endpoint: None,
                launch_env: BTreeMap::from([
                    ("AMBER_CONFIG_TENANT".to_string(), "acme-local".to_string()),
                    (
                        "AMBER_CONFIG_CATALOG_TOKEN".to_string(),
                        "demo-token".to_string(),
                    ),
                ]),
            },
        )
        .expect("site supervisor plan should be written");

        assert_eq!(
            read_compose_launch_env(&run_root, "compose_local")
                .expect("compose launch env should be readable"),
            BTreeMap::from([
                (
                    "AMBER_CONFIG_CATALOG_TOKEN".to_string(),
                    "demo-token".to_string()
                ),
                ("AMBER_CONFIG_TENANT".to_string(), "acme-local".to_string()),
            ])
        );
    }

    #[test]
    fn parse_process_table_reads_ps_output() {
        assert_eq!(
            parse_process_table("  42     1\n  84   42\n").expect("process table should parse"),
            HashMap::from([(42, 1), (84, 42)])
        );
    }

    #[cfg(unix)]
    #[test]
    fn parse_process_status_code_reads_ps_state() {
        assert_eq!(parse_process_status_code("S+\n"), Some('S'));
        assert_eq!(parse_process_status_code("z\n"), Some('Z'));
        assert_eq!(parse_process_status_code("\n"), None);
    }

    #[cfg(unix)]
    #[test]
    fn collect_process_tree_postorder_visits_descendants_before_parent() {
        let children_by_parent = HashMap::from([(1, vec![2, 3]), (2, vec![4]), (3, vec![5, 6])]);
        let mut ordered = Vec::new();
        collect_process_tree_postorder(1, &children_by_parent, &mut ordered);
        assert_eq!(ordered, vec![4, 2, 5, 6, 3, 1]);
    }

    #[test]
    fn container_host_from_resolved_ip_matches_provider_and_consumer_kind() {
        assert_eq!(
            container_host_from_resolved_ip(
                SiteKind::Compose,
                SiteKind::Direct,
                Some("172.17.0.1"),
            ),
            "127.0.0.1"
        );
        assert_eq!(
            container_host_from_resolved_ip(SiteKind::Compose, SiteKind::Vm, Some("172.17.0.1"),),
            "127.0.0.1"
        );
        assert_eq!(
            container_host_from_resolved_ip(SiteKind::Vm, SiteKind::Compose, Some("172.17.0.1"),),
            CONTAINER_HOST_ALIAS
        );
        assert_eq!(
            container_host_from_resolved_ip(
                SiteKind::Direct,
                SiteKind::Compose,
                Some("172.17.0.1"),
            ),
            CONTAINER_HOST_ALIAS
        );
        assert_eq!(
            container_host_from_resolved_ip(
                SiteKind::Kubernetes,
                SiteKind::Compose,
                Some("172.17.0.1"),
            ),
            "172.17.0.1"
        );
        assert_eq!(
            container_host_from_resolved_ip(SiteKind::Vm, SiteKind::Kubernetes, Some("172.17.0.1"),),
            "172.17.0.1"
        );
        assert_eq!(
            container_host_from_resolved_ip(SiteKind::Vm, SiteKind::Kubernetes, None),
            CONTAINER_HOST_ALIAS
        );
    }

    #[test]
    fn containerized_consumers_bridge_runtime_links() {
        assert!(link_needs_bridge_proxy(SiteKind::Direct, SiteKind::Compose));
        assert!(link_needs_bridge_proxy(SiteKind::Vm, SiteKind::Compose));
        assert!(link_needs_bridge_proxy(
            SiteKind::Kubernetes,
            SiteKind::Compose
        ));
        assert!(link_needs_bridge_proxy(
            SiteKind::Direct,
            SiteKind::Kubernetes
        ));
        assert!(link_needs_bridge_proxy(SiteKind::Vm, SiteKind::Kubernetes));
        assert!(link_needs_bridge_proxy(
            SiteKind::Kubernetes,
            SiteKind::Kubernetes
        ));
        assert!(link_needs_bridge_proxy(
            SiteKind::Compose,
            SiteKind::Compose
        ));
        assert!(!link_needs_bridge_proxy(SiteKind::Vm, SiteKind::Direct));
    }

    #[test]
    fn bridge_proxy_bind_and_probe_addresses_match_consumer_kind() {
        let compose_listen = bridge_proxy_bind_addr(SiteKind::Compose, 41000);
        assert_eq!(compose_listen, SocketAddr::from(([0, 0, 0, 0], 41000)));
        assert_eq!(
            bridge_proxy_probe_addr(compose_listen),
            SocketAddr::from(([127, 0, 0, 1], 41000))
        );

        let kind_listen = bridge_proxy_bind_addr(SiteKind::Kubernetes, 42000);
        assert_eq!(kind_listen, SocketAddr::from(([0, 0, 0, 0], 42000)));
        assert_eq!(
            bridge_proxy_probe_addr(kind_listen),
            SocketAddr::from(([127, 0, 0, 1], 42000))
        );

        let direct_listen = bridge_proxy_bind_addr(SiteKind::Direct, 43000);
        assert_eq!(direct_listen, SocketAddr::from(([127, 0, 0, 1], 43000)));
        assert_eq!(bridge_proxy_probe_addr(direct_listen), direct_listen);
    }

    #[test]
    fn bridge_proxy_external_url_uses_consumer_aware_host() {
        assert_eq!(
            bridge_proxy_external_url(44000, NetworkProtocol::Http, SiteKind::Compose)
                .expect("http bridge proxy url should be valid"),
            "http://host.docker.internal:44000"
        );
        assert_eq!(
            bridge_proxy_external_url(45000, NetworkProtocol::Http, SiteKind::Kubernetes)
                .expect("http bridge proxy url should be valid"),
            format!(
                "http://{}:45000",
                bridge_proxy_host_for_consumer(SiteKind::Kubernetes)
            )
        );
    }

    #[test]
    fn outside_proxy_mesh_listener_stays_loopback_for_local_consumers() {
        let context = RunOutsideProxyContext {
            mesh_scope: "scope".to_string(),
            sites: BTreeMap::from([(
                "direct".to_string(),
                test_launched_site_with_kind(SiteKind::Direct),
            )]),
            exports: BTreeMap::new(),
            slots: BTreeMap::from([(
                "api".to_string(),
                RunOutsideSlot {
                    required: true,
                    kind: CapabilityKind::Http,
                    url_env: "AMBER_EXTERNAL_SLOT_API_URL".to_string(),
                    consumer_sites: vec!["direct".to_string()],
                },
            )]),
        };

        assert_eq!(
            outside_proxy_mesh_listen_addr(
                &context,
                &[("api".to_string(), "http://127.0.0.1:9000".to_string())],
                48000,
            )
            .expect("outside proxy bind addr"),
            SocketAddr::from(([127, 0, 0, 1], 48000))
        );
    }

    #[test]
    fn outside_proxy_mesh_listener_expands_for_container_consumers() {
        let context = RunOutsideProxyContext {
            mesh_scope: "scope".to_string(),
            sites: BTreeMap::from([
                (
                    "direct".to_string(),
                    test_launched_site_with_kind(SiteKind::Direct),
                ),
                (
                    "compose".to_string(),
                    test_launched_site_with_kind(SiteKind::Compose),
                ),
            ]),
            exports: BTreeMap::new(),
            slots: BTreeMap::from([(
                "api".to_string(),
                RunOutsideSlot {
                    required: true,
                    kind: CapabilityKind::Http,
                    url_env: "AMBER_EXTERNAL_SLOT_API_URL".to_string(),
                    consumer_sites: vec!["direct".to_string(), "compose".to_string()],
                },
            )]),
        };

        assert_eq!(
            outside_proxy_mesh_listen_addr(
                &context,
                &[("api".to_string(), "http://127.0.0.1:9000".to_string())],
                49000,
            )
            .expect("outside proxy bind addr"),
            SocketAddr::from(([0, 0, 0, 0], 49000))
        );
    }

    #[test]
    fn bridge_proxy_export_binding_uses_selected_listen_addr() {
        assert_eq!(
            bridge_proxy_export_binding("api", SocketAddr::from(([127, 0, 0, 1], 46000))),
            "api=127.0.0.1:46000"
        );
        assert_eq!(
            bridge_proxy_export_binding("api", SocketAddr::from(([0, 0, 0, 0], 47000))),
            "api=0.0.0.0:47000"
        );
    }

    fn test_launched_site_with_kind(kind: SiteKind) -> LaunchedSite {
        LaunchedSite {
            receipt: SiteReceipt {
                kind,
                artifact_dir: "/tmp/artifact".to_string(),
                supervisor_pid: 1,
                process_pid: None,
                compose_project: None,
                context: None,
                kubernetes_namespace: None,
                port_forward_pid: None,
                router_mesh_addr: None,
                router_control: None,
                router_identity_id: None,
                router_public_key_b64: None,
            },
            router_identity: MeshIdentityPublic {
                id: format!("/site/{kind:?}"),
                public_key: [0; 32],
                mesh_scope: None,
            },
            router_addr: SocketAddr::from(([127, 0, 0, 1], 24000)),
            router_control: ControlEndpoint::Tcp("127.0.0.1:24100".to_string()),
        }
    }

    #[test]
    fn kubernetes_sites_get_startup_budget_after_workloads_are_ready() {
        assert_eq!(
            site_ready_timeout_for_kind(SiteKind::Kubernetes),
            KUBERNETES_WORKLOAD_READY_TIMEOUT + KUBERNETES_SITE_READY_BUFFER
        );
    }

    #[test]
    fn kubernetes_namespace_name_is_run_scoped() {
        assert_eq!(
            kubernetes_namespace_name("run-1234abcd", "kind_c"),
            "amber-run-1234abcd-kind-c"
        );
        assert_ne!(
            kubernetes_namespace_name("run-1234abcd", "kind_c"),
            kubernetes_namespace_name("run-5678efgh", "kind_c")
        );
    }

    #[test]
    fn prepare_kubernetes_artifact_namespace_rewrites_kustomization_namespace() {
        let temp = tempdir().expect("tempdir should be created");
        let kustomization = temp.path().join("kustomization.yaml");
        fs::write(
            &kustomization,
            "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nnamespace: \
             scenario-old\n",
        )
        .expect("kustomization should be written");

        let namespace =
            prepare_kubernetes_artifact_namespace("run-1234abcd", "kind_c", temp.path())
                .expect("artifact namespace should be prepared");

        assert_eq!(namespace, "amber-run-1234abcd-kind-c");
        assert_eq!(
            fs::read_to_string(&kustomization).expect("kustomization should be readable"),
            "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nnamespace: \
             amber-run-1234abcd-kind-c\n"
        );
    }

    #[test]
    fn external_slot_name_from_env_var_restores_slot_name() {
        assert_eq!(
            external_slot_name_from_env_var("AMBER_EXTERNAL_SLOT_API_URL"),
            "api"
        );
    }

    #[test]
    fn external_slot_env_for_site_skips_missing_weak_provider() {
        let env = external_slot_env_for_site(
            "consumer_site",
            SiteKind::Direct,
            &[RunLink {
                provider_site: "provider_site".to_string(),
                consumer_site: "consumer_site".to_string(),
                provider_component: "/provider".to_string(),
                provide: "api".to_string(),
                consumer_component: "/consumer".to_string(),
                slot: "upstream".to_string(),
                weak: true,
                protocol: NetworkProtocol::Http,
                export_name: "amber_export_provider_api_http".to_string(),
                external_slot_name: "amber_link_consumer_provider_api_http".to_string(),
            }],
            &BTreeMap::new(),
        )
        .expect("weak links should not require a launched provider");
        assert!(env.is_empty());
    }

    #[test]
    fn maybe_resolve_proxy_run_target_resolves_run_id_and_prefers_live_state() {
        let temp = tempdir().expect("tempdir should exist");
        let storage_root = temp.path();
        let run_id = "run-123";
        let run_root = storage_root.join("runs").join(run_id);
        let artifact_dir = run_root.join("sites").join("direct_local").join("artifact");
        fs::create_dir_all(&artifact_dir).expect("artifact dir should exist");
        let state_root = run_root.join("state");
        fs::create_dir_all(state_root.join("direct_local")).expect("state dir should exist");

        let receipt = RunReceipt {
            schema: RECEIPT_SCHEMA.to_string(),
            version: RECEIPT_VERSION,
            run_id: run_id.to_string(),
            mesh_scope: "mesh.scope.test".to_string(),
            plan_path: run_plan_path(&run_root).display().to_string(),
            source_plan_path: None,
            run_root: run_root.display().to_string(),
            observability: None,
            bridge_proxies: Vec::new(),
            sites: BTreeMap::from([(
                "direct_local".to_string(),
                test_site_receipt(
                    SiteKind::Direct,
                    &artifact_dir,
                    Some("unix:///receipt.sock"),
                    Some("127.0.0.1:18080"),
                ),
            )]),
        };
        write_json(&receipt_path(&run_root), &receipt).expect("receipt should serialize");
        write_json(
            &site_state_path(&state_root, "direct_local"),
            &test_site_state(
                run_id,
                "direct_local",
                SiteKind::Direct,
                &artifact_dir,
                Some("unix:///live.sock"),
                Some("127.0.0.1:18081"),
            ),
        )
        .expect("state should serialize");

        let resolved =
            maybe_resolve_proxy_run_target(run_id, Some("direct_local"), Some(storage_root))
                .expect("run target resolution should succeed")
                .expect("run target should resolve");

        assert_eq!(
            resolved.artifact_dir,
            artifact_dir
                .canonicalize()
                .expect("artifact dir should canonicalize")
        );
        assert_eq!(
            resolved.router_control_addr.as_deref(),
            Some("unix:///live.sock")
        );
        assert_eq!(
            resolved.router_addr,
            Some(
                "127.0.0.1:18081"
                    .parse::<SocketAddr>()
                    .expect("socket addr should parse")
            )
        );
    }

    #[test]
    fn maybe_resolve_proxy_run_target_requires_site_for_multi_site_run() {
        let temp = tempdir().expect("tempdir should exist");
        let storage_root = temp.path();
        let run_id = "run-456";
        let run_root = storage_root.join("runs").join(run_id);
        let direct_artifact = run_root.join("sites").join("direct_local").join("artifact");
        let compose_artifact = run_root
            .join("sites")
            .join("compose_local")
            .join("artifact");
        fs::create_dir_all(&direct_artifact).expect("direct artifact dir should exist");
        fs::create_dir_all(&compose_artifact).expect("compose artifact dir should exist");

        let receipt = RunReceipt {
            schema: RECEIPT_SCHEMA.to_string(),
            version: RECEIPT_VERSION,
            run_id: run_id.to_string(),
            mesh_scope: "mesh.scope.test".to_string(),
            plan_path: run_plan_path(&run_root).display().to_string(),
            source_plan_path: None,
            run_root: run_root.display().to_string(),
            observability: None,
            bridge_proxies: Vec::new(),
            sites: BTreeMap::from([
                (
                    "compose_local".to_string(),
                    test_site_receipt(
                        SiteKind::Compose,
                        &compose_artifact,
                        Some("unix:///compose.sock"),
                        Some("127.0.0.1:19090"),
                    ),
                ),
                (
                    "direct_local".to_string(),
                    test_site_receipt(
                        SiteKind::Direct,
                        &direct_artifact,
                        Some("unix:///direct.sock"),
                        Some("127.0.0.1:19091"),
                    ),
                ),
            ]),
        };
        write_json(&receipt_path(&run_root), &receipt).expect("receipt should serialize");

        let err = maybe_resolve_proxy_run_target(run_id, None, Some(storage_root))
            .expect_err("multi-site run ids should require --site");
        let message = err.to_string();
        assert!(
            message.contains("contains multiple sites"),
            "expected multi-site guidance, got: {message}"
        );
        assert!(
            message.contains("--site <site-id>"),
            "expected --site guidance, got: {message}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stop_run_forces_supervisor_shutdown_and_cleans_up() {
        let temp = tempdir().expect("tempdir should exist");
        let storage_root = temp.path();
        let run_id = "run-stuck";
        let run_root = storage_root.join("runs").join(run_id);
        let artifact_dir = run_root.join("sites").join("direct_local").join("artifact");
        fs::create_dir_all(&artifact_dir).expect("artifact dir should exist");

        let mut stubborn_supervisor = Command::new("sh")
            .arg("-c")
            .arg("trap '' TERM; while :; do sleep 1 & wait $!; done")
            .spawn()
            .expect("stubborn supervisor should spawn");

        let receipt = RunReceipt {
            schema: RECEIPT_SCHEMA.to_string(),
            version: RECEIPT_VERSION,
            run_id: run_id.to_string(),
            mesh_scope: "mesh.scope.test".to_string(),
            plan_path: run_plan_path(&run_root).display().to_string(),
            source_plan_path: None,
            run_root: run_root.display().to_string(),
            observability: None,
            bridge_proxies: Vec::new(),
            sites: BTreeMap::from([(
                "direct_local".to_string(),
                SiteReceipt {
                    supervisor_pid: stubborn_supervisor.id(),
                    ..test_site_receipt(
                        SiteKind::Direct,
                        &artifact_dir,
                        Some("unix:///receipt.sock"),
                        Some("127.0.0.1:18080"),
                    )
                },
            )]),
        };
        write_json(&receipt_path(&run_root), &receipt).expect("receipt should serialize");

        let state_root = run_root.join("state");
        let mut state = test_site_state(
            run_id,
            "direct_local",
            SiteKind::Direct,
            &artifact_dir,
            Some("unix:///live.sock"),
            Some("127.0.0.1:18081"),
        );
        state.status = SiteLifecycleStatus::Stopped;
        state.supervisor_pid = stubborn_supervisor.id();
        write_json(&site_state_path(&state_root, "direct_local"), &state)
            .expect("state should serialize");

        let result = stop_run(run_id, Some(storage_root)).await;

        let _ = stubborn_supervisor.kill();
        let _ = stubborn_supervisor.wait();

        result.expect("stop_run should force the supervisor down and succeed");
        assert!(
            !receipt_path(&run_root).is_file(),
            "receipt should be removed after forced shutdown cleanup"
        );
        assert!(
            stop_marker_path(&run_root).is_file(),
            "stop marker should be written for supervisors"
        );

        let updated_state: SiteManagerState = read_json(
            &site_state_path(&state_root, "direct_local"),
            "site manager state",
        )
        .expect("updated state should deserialize");
        assert_eq!(updated_state.status, SiteLifecycleStatus::Stopped);
        assert!(
            updated_state.last_error.as_deref().is_some_and(|value| {
                value.contains("forcing shutdown")
                    || value.contains("exited before confirming stop")
            }),
            "expected escalated shutdown cleanup to be recorded, got: {:?}",
            updated_state.last_error
        );
    }
}
