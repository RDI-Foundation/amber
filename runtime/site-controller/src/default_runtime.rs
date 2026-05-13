#[cfg(target_os = "linux")]
use std::net::Ipv4Addr;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    env, fs,
    io::{Read as _, Write as _},
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, OnceLock},
    time::Duration,
};

use amber_compiler::{
    mesh::ProxyMetadata,
    reporter::{
        direct::{DirectPlan, DirectRuntimeUrlSource},
        vm::VmPlan,
    },
    run_plan::{RunLink, SiteKind},
};
use amber_manifest::NetworkProtocol;
use amber_mesh::{
    HttpRoutePlugin, InboundRoute, InboundTarget, MESH_CONFIG_FILENAME, MESH_IDENTITY_FILENAME,
    MeshConfigPublic, MeshIdentity, MeshIdentityPublic, MeshIdentitySecret, MeshPeer,
    MeshPeerTemplate, MeshProtocol, MeshProvisionOutput, MeshProvisionPlan, MeshProvisionTarget,
    MeshProvisionTargetKind, OutboundRoute, component_route_id, router_dynamic_export_route_id,
    router_export_route_id,
};
use amber_proxy::{
    ControlEndpoint, apply_route_overlay_with_retry, load_output_proxy_metadata,
    revoke_route_overlay_with_retry,
};
use miette::{Context as _, IntoDiagnostic as _, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue};
use sha2::{Digest as _, Sha256};
use tokio::{
    sync::Mutex as AsyncMutex,
    time::{Instant, sleep},
};
use url::Url;

mod child_runtime;
mod compose_controller;
mod dynamic_routes;
mod kubernetes_controller;
mod site_artifacts;
mod site_runtime_support;

pub(crate) use self::child_runtime::{
    default_site_controller_runtime, runtime_plan_for_site_from_controller_plan,
};
pub(super) use self::site_artifacts::*;
pub use self::{
    child_runtime::cleanup_dynamic_site_children,
    compose_controller::{
        inject_compose_site_controller, inject_compose_site_controller_with_mount_sources,
    },
    kubernetes_controller::inject_kubernetes_site_controller,
    site_artifacts::{
        SiteControllerPeerRouterRoute, inject_site_controller_peer_router_routes,
        set_compose_router_published_mesh_port, set_site_artifact_mesh_identity_seed,
    },
    site_runtime_support::{
        host_service_bind_addr_for_consumer, observability_endpoint_for_site,
        prepare_kubernetes_artifact_namespace, reserve_host_port, reserve_loopback_port,
        router_mesh_addr_for_consumer, site_controller_peer_router_url, walk_files,
    },
};
use self::{
    child_runtime::{
        DynamicComposeChildMetadata, SiteControllerRuntimeApp, SiteControllerRuntimeChildRecord,
        SiteControllerRuntimeState, StoredRouteOverlayPayload, dynamic_compose_child_metadata_path,
        dynamic_route_overlay_path, load_dynamic_proxy_exports_metadata,
        site_controller_runtime_child_runtime_root, site_controller_runtime_state_path,
        write_dynamic_route_overlay_payload,
    },
    dynamic_routes::*,
    site_runtime_support::*,
};
use super::*;
use crate::{
    http::{read_json, write_json},
    planner::{
        LocalChildRuntimeSpec, build_desired_site_artifact_files, build_local_child_runtime_spec,
    },
    runtime_api::{SharedSiteControllerRuntime, SiteControllerRuntime},
    state::{FrameworkControlState, LiveChildRecord},
};

const DYNAMIC_COMPOSE_CHILD_SCHEMA: &str = "amber.run.dynamic_compose_child";
const DYNAMIC_COMPOSE_CHILD_VERSION: u32 = 1;
const DYNAMIC_COMPOSE_MESH_ROOT: &str = ".amber/mesh";
const DYNAMIC_ROUTE_OVERLAY_FILENAME: &str = "site-router-overlay.json";
const DYNAMIC_PROXY_EXPORTS_FILENAME: &str = "proxy-exports.json";
const COMPONENT_CONTROL_SOCKET_PATH_IN_VOLUME: &str = "/router-control.sock";
const COMPOSE_PROVISIONER_SERVICE_NAME: &str = "amber-provisioner";
const COMPOSE_ROUTER_SERVICE_NAME: &str = "amber-router";
const KUBERNETES_MESH_PROVISION_CONFIGMAP_PATH: &str = "01-configmaps/amber-mesh-provision.yaml";
const KUBERNETES_PROVISIONER_ROLE_PATH: &str = "02-rbac/amber-provisioner-role.yaml";
const KUBERNETES_PROVISIONER_ROLEBINDING_PATH: &str = "02-rbac/amber-provisioner-rolebinding.yaml";
const KUBERNETES_PROVISIONER_SERVICE_ACCOUNT_PATH: &str = "02-rbac/amber-provisioner-sa.yaml";
const KUBERNETES_ROUTER_EXTERNAL_SECRET_NAME: &str = "amber-router-external";
const KUBERNETES_ROUTER_COMPONENT_NAME: &str = "amber-router";
const SITE_PLAN_SCHEMA: &str = "amber.run.site_supervisor_plan";
const SITE_PLAN_VERSION: u32 = 2;
const SITE_CONTROLLER_RUNTIME_STATE_SCHEMA: &str = "amber.run.site_controller_runtime_state";
const SITE_CONTROLLER_RUNTIME_STATE_VERSION: u32 = 1;
const DESIRED_LINKS_SCHEMA: &str = "amber.run.desired_links";
const DESIRED_LINKS_VERSION: u32 = 1;
const DEFAULT_EXTERNAL_ENV_FILE: &str = "router-external.env";
const DEFAULT_K8S_OTEL_UPSTREAM: &str = "http://host.docker.internal:18890";
const CONTAINER_HOST_ALIAS: &str = "host.docker.internal";
const KUBERNETES_WORKLOAD_READY_TIMEOUT: Duration = Duration::from_secs(120);
const KUBERNETES_SITE_READY_BUFFER: Duration = Duration::from_secs(30);
const COMPOSE_EGRESS_SUBNET_COUNT: u32 = 1 << 18;

static KUBERNETES_CONTAINER_HOST_IP: OnceLock<Option<String>> = OnceLock::new();

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    compose_consumer_router_mesh_addr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kubernetes_consumer_router_mesh_addr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    router_identity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    router_public_key_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    site_controller_url: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    site_controller_url: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    launch_env: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct DesiredLinkState {
    schema: String,
    version: u32,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    external_slots: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    export_peers: Vec<DesiredExportPeer>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    external_slot_overlays: BTreeMap<String, DesiredExternalSlotOverlay>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    export_peer_overlays: BTreeMap<String, DesiredExportPeerOverlay>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct DesiredExportPeer {
    export_name: String,
    peer_id: String,
    peer_key_b64: String,
    protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    route_id: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct DirectRuntimeState {
    #[serde(default)]
    ready: bool,
    #[serde(default)]
    slot_ports_by_component: BTreeMap<usize, BTreeMap<String, u16>>,
    #[serde(default)]
    slot_route_ports_by_component: BTreeMap<usize, BTreeMap<String, Vec<u16>>>,
    #[serde(default)]
    dynamic_caps_port_by_component: BTreeMap<usize, u16>,
    #[serde(default)]
    component_mesh_port_by_id: BTreeMap<usize, u16>,
    #[serde(default)]
    router_mesh_port: Option<u16>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct VmRuntimeState {
    #[serde(default)]
    slot_ports_by_component: BTreeMap<usize, BTreeMap<String, u16>>,
    #[serde(default)]
    slot_route_ports_by_component: BTreeMap<usize, BTreeMap<String, Vec<u16>>>,
    #[serde(default)]
    route_host_ports_by_component: BTreeMap<usize, BTreeMap<String, Vec<u16>>>,
    #[serde(default)]
    endpoint_forwards_by_component: BTreeMap<usize, BTreeMap<u16, u16>>,
    #[serde(default)]
    component_mesh_port_by_id: BTreeMap<usize, u16>,
    #[serde(default)]
    router_mesh_port: Option<u16>,
}

fn required_str<'a>(value: Option<&'a str>, label: &str) -> Result<&'a str> {
    value.ok_or_else(|| miette::miette!("missing {label}"))
}

fn direct_runtime_state_path(plan_root: &Path) -> PathBuf {
    plan_root.join(".amber").join("direct-runtime.json")
}

fn direct_current_control_socket_path(plan_root: &Path) -> PathBuf {
    amber_mesh::stable_temp_socket_path("amber-direct-control", "current", plan_root)
}

#[cfg(unix)]
fn ensure_direct_control_socket_link(link: &Path, target: &Path, description: &str) -> Result<()> {
    if fs::read_link(link)
        .ok()
        .is_some_and(|existing_target| existing_target == target)
    {
        return Ok(());
    }
    if fs::symlink_metadata(link).is_ok() {
        fs::remove_file(link)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to remove stale {description} {}", link.display()))?;
    }
    std::os::unix::fs::symlink(target, link)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create {description} {} -> {}",
                link.display(),
                target.display()
            )
        })
}

#[cfg(not(unix))]
fn ensure_direct_control_socket_link(link: &Path, target: &Path, description: &str) -> Result<()> {
    let _ = (link, target, description);
    Err(miette::miette!(
        "direct runtime control sockets require unix symlink support"
    ))
}

fn vm_current_control_socket_path(plan_root: &Path) -> PathBuf {
    amber_mesh::stable_temp_socket_path("amber-vm-control", "current", plan_root)
}

#[cfg(unix)]
fn ensure_control_socket_link(link: &Path, target: &Path, description: &str) -> Result<()> {
    if fs::read_link(link)
        .ok()
        .is_some_and(|existing_target| existing_target == target)
    {
        return Ok(());
    }
    if fs::symlink_metadata(link).is_ok() {
        fs::remove_file(link)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to remove stale {description} {}", link.display()))?;
    }
    std::os::unix::fs::symlink(target, link)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create {description} {} -> {}",
                link.display(),
                target.display()
            )
        })
}

#[cfg(not(unix))]
fn ensure_control_socket_link(link: &Path, target: &Path, description: &str) -> Result<()> {
    let _ = (link, target, description);
    Err(miette::miette!(
        "vm runtime control sockets require unix symlink support"
    ))
}

fn write_vm_runtime_state(plan_root: &Path, state: &VmRuntimeState) -> Result<()> {
    let path = plan_root.join(".amber").join("vm-runtime.json");
    let parent = path
        .parent()
        .ok_or_else(|| miette::miette!("invalid vm runtime state path"))?;
    fs::create_dir_all(parent)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create vm runtime dir {}", parent.display()))?;
    write_json(&path, state)
}

const TCG_VM_STARTUP_TIMEOUT: Duration = Duration::from_secs(720);

pub fn vm_uses_tcg_accel() -> bool {
    #[cfg(target_os = "macos")]
    {
        env::var_os("AMBER_VM_FORCE_TCG").is_some()
    }

    #[cfg(target_os = "linux")]
    {
        env::var_os("AMBER_VM_FORCE_TCG").is_some() || !Path::new("/dev/kvm").exists()
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        env::var_os("AMBER_VM_FORCE_TCG").is_some()
    }
}

pub fn vm_endpoint_forward_ready_timeout() -> Duration {
    if vm_uses_tcg_accel() {
        TCG_VM_STARTUP_TIMEOUT
    } else {
        Duration::from_secs(120)
    }
}

fn vm_endpoint_forward_ready_timeout_for_runtime_plan(
    plan: &SiteControllerRuntimePlan,
) -> Duration {
    plan.vm_endpoint_forward_ready_timeout_secs
        .map(Duration::from_secs)
        .unwrap_or_else(vm_endpoint_forward_ready_timeout)
}

fn required_existing_mesh_peer_identities(
    plan: &MeshProvisionPlan,
    available_peer_identities_by_id: &BTreeMap<String, MeshIdentityPublic>,
) -> Result<BTreeMap<String, MeshIdentityPublic>> {
    let target_ids = plan
        .targets
        .iter()
        .map(|target| target.config.identity.id.as_str())
        .collect::<BTreeSet<_>>();
    let required_peer_ids = plan
        .targets
        .iter()
        .flat_map(|target| target.config.peers.iter())
        .filter(|peer| !target_ids.contains(peer.id.as_str()))
        .map(|peer| peer.id.as_str())
        .collect::<BTreeSet<_>>();

    required_peer_ids
        .into_iter()
        .map(|peer_id| {
            let identity = available_peer_identities_by_id
                .get(peer_id)
                .cloned()
                .ok_or_else(|| {
                    miette::miette!(
                        "mesh provision plan requires existing peer identity {peer_id}, but it is \
                         not currently available"
                    )
                })?;
            Ok((peer_id.to_string(), identity))
        })
        .collect()
}

fn mesh_output_dir_for_target(root: &Path, target: &MeshProvisionTarget) -> Result<PathBuf> {
    match &target.output {
        MeshProvisionOutput::Filesystem { dir } => {
            let path = Path::new(dir);
            if path.is_absolute() {
                return Err(miette::miette!(
                    "mesh provision plan contains absolute filesystem output path {}",
                    path.display()
                ));
            }
            Ok(root.join(path))
        }
        MeshProvisionOutput::KubernetesSecret { name, .. } => Err(miette::miette!(
            "local runtime does not support kubernetes provision target {name}"
        )),
    }
}

fn provision_mesh_filesystem_with_peer_identities(
    plan: &MeshProvisionPlan,
    root: &Path,
    existing_peer_identities_by_id: &BTreeMap<String, MeshIdentityPublic>,
) -> Result<()> {
    let mut identities: HashMap<String, MeshIdentity> = HashMap::new();
    for identity in existing_peer_identities_by_id.values() {
        identities.insert(
            identity.id.clone(),
            MeshIdentity {
                id: identity.id.clone(),
                public_key: identity.public_key,
                private_key: [0; 64],
                mesh_scope: identity.mesh_scope.clone(),
            },
        );
    }
    for target in &plan.targets {
        let id = target.config.identity.id.clone();
        let mesh_scope = target.config.identity.mesh_scope.clone();
        identities
            .entry(id)
            .or_insert_with(|| match plan.identity_seed.as_deref() {
                Some(seed) => {
                    MeshIdentity::derive(target.config.identity.id.clone(), mesh_scope, seed)
                }
                None => MeshIdentity::generate(target.config.identity.id.clone(), mesh_scope),
            });
    }
    for target in &plan.targets {
        let output_dir = mesh_output_dir_for_target(root, target)?;
        fs::create_dir_all(&output_dir)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "failed to create mesh output directory {}",
                    output_dir.display()
                )
            })?;
        let identity = identities
            .get(&target.config.identity.id)
            .ok_or_else(|| {
                miette::miette!(
                    "missing generated identity for {}",
                    target.config.identity.id
                )
            })?
            .clone();
        let identity_secret = MeshIdentitySecret::from_identity(&identity);
        let public_config = target.config.to_public_config(&identities).map_err(|err| {
            miette::miette!(
                "failed to render mesh config for {}: {err}",
                target.config.identity.id
            )
        })?;
        write_json(&output_dir.join(MESH_IDENTITY_FILENAME), &identity_secret)?;
        write_json(&output_dir.join(MESH_CONFIG_FILENAME), &public_config)?;
    }
    Ok(())
}

fn project_existing_peer_identities_into_mesh_config(
    path: &Path,
    existing_peer_identities_by_id: &BTreeMap<String, MeshIdentityPublic>,
) -> Result<()> {
    if existing_peer_identities_by_id.is_empty() || !path.is_file() {
        return Ok(());
    }
    let mut config: MeshConfigPublic = read_json(path, "mesh config")?;
    let canonical_mesh_scope = existing_peer_identities_by_id
        .values()
        .find_map(|identity| identity.mesh_scope.clone());
    let mut changed = false;
    if let Some(identity) = existing_peer_identities_by_id.get(&config.identity.id) {
        if config.identity.public_key != identity.public_key
            || config.identity.mesh_scope != identity.mesh_scope
        {
            config.identity.public_key = identity.public_key;
            config.identity.mesh_scope = identity.mesh_scope.clone();
            changed = true;
        }
    } else if let Some(mesh_scope) = canonical_mesh_scope.as_ref()
        && config.identity.mesh_scope.as_deref() != Some(mesh_scope.as_str())
    {
        config.identity.mesh_scope = Some(mesh_scope.clone());
        changed = true;
    }
    for peer in &mut config.peers {
        let Some(identity) = existing_peer_identities_by_id.get(&peer.id) else {
            continue;
        };
        if peer.public_key != identity.public_key {
            peer.public_key = identity.public_key;
            changed = true;
        }
    }
    if changed {
        write_json(path, &config)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn rewrite_peer_addr_for_slirp_gateway(peer_addr: &str) -> String {
    let Ok(addr) = peer_addr.parse::<SocketAddr>() else {
        return peer_addr.to_string();
    };
    if !addr.ip().is_loopback() {
        return peer_addr.to_string();
    }
    SocketAddr::from((Ipv4Addr::new(10, 0, 2, 2), addr.port())).to_string()
}

#[derive(Debug, Deserialize)]
struct KubernetesSecretPayload {
    #[serde(default)]
    data: BTreeMap<String, String>,
}
fn rewrite_dynamic_proxy_metadata(
    artifact_root: &Path,
    proxy_exports: &BTreeMap<String, DynamicProxyExportRecord>,
    kind: SiteKind,
) -> Result<()> {
    if proxy_exports.is_empty() {
        return Ok(());
    }
    if kind == SiteKind::Compose {
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
        let exports = proxy_exports
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
        let exports = proxy_exports
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

pub(super) fn yaml_string(value: &str) -> serde_yaml::Value {
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

pub(super) fn compose_services_mut<'a>(
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

pub fn assign_compose_egress_network_subnets(
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
    plan: &SiteControllerRuntimePlan,
    published_children: &[SiteControllerRuntimeChildRecord],
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
    workloads: &KubernetesArtifactWorkloads,
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
    plan: &SiteControllerRuntimePlan,
    timeout: Duration,
) -> Result<()> {
    debug_assert_eq!(plan.kind, SiteKind::Kubernetes);

    let deadline = Instant::now() + timeout;
    loop {
        let state_path = Path::new(&plan.site_state_root).join("manager-state.json");
        let manager_state = if state_path.is_file() {
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
            Some(state)
        } else {
            None
        };

        if let Some((control_target, mesh_target)) =
            kubernetes_router_ready_targets(plan, manager_state.as_ref())?
            && probe_kubernetes_router_control_ready(&control_target, Duration::from_millis(250))
                .await?
            && router_mesh_listener_ready_target(&mesh_target, Duration::from_millis(250)).await
        {
            return Ok(());
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

fn kubernetes_router_ready_targets(
    plan: &SiteControllerRuntimePlan,
    manager_state: Option<&SiteManagerState>,
) -> Result<Option<(String, String)>> {
    if let Some(control_target) = plan.local_router_control.as_deref() {
        return Ok(Some((
            control_target.to_string(),
            kubernetes_local_router_mesh_target(plan)?,
        )));
    }

    let Some(state) = manager_state else {
        return Ok(None);
    };
    if !matches!(state.status, SiteLifecycleStatus::Running) {
        return Ok(None);
    }
    let (Some(control), Some(mesh_addr)) = (
        state.router_control.as_deref(),
        state.router_mesh_addr.as_deref(),
    ) else {
        return Ok(None);
    };
    let control_addr: SocketAddr = control
        .parse()
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid kubernetes router control addr `{control}`"))?;
    let mesh_addr: SocketAddr = mesh_addr
        .parse()
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid kubernetes router mesh addr `{mesh_addr}`"))?;
    Ok(Some((control_addr.to_string(), mesh_addr.to_string())))
}

fn kubernetes_local_router_mesh_target(plan: &SiteControllerRuntimePlan) -> Result<String> {
    let control_target = plan.local_router_control.as_deref().ok_or_else(|| {
        miette::miette!(
            "kubernetes site `{}` is missing its local router control endpoint",
            plan.site_id
        )
    })?;
    let (host, _) = control_target.rsplit_once(':').ok_or_else(|| {
        miette::miette!(
            "kubernetes site `{}` has invalid local router control endpoint `{control_target}`",
            plan.site_id
        )
    })?;
    let mesh_port = plan.router_mesh_port.ok_or_else(|| {
        miette::miette!(
            "kubernetes site `{}` is missing its router mesh port",
            plan.site_id
        )
    })?;
    Ok(format!("{host}:{mesh_port}"))
}

async fn router_mesh_listener_ready_target(target: &str, timeout: Duration) -> bool {
    matches!(
        tokio::time::timeout(timeout, tokio::net::TcpStream::connect(target)).await,
        Ok(Ok(_))
    )
}

async fn probe_kubernetes_router_control_ready(target: &str, timeout: Duration) -> Result<bool> {
    let url = format!("http://{target}/identity");
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .into_diagnostic()
        .wrap_err("failed to build kubernetes router readiness client")?;
    let response = match client.get(&url).send().await {
        Ok(response) => response,
        Err(err) if err.is_connect() || err.is_timeout() => return Ok(false),
        Err(err) => {
            return Err(miette::miette!(
                "failed to probe kubernetes router control at {target}: {err}"
            ));
        }
    };
    if !response.status().is_success() {
        return Ok(false);
    }
    Ok(response.json::<MeshIdentityPublic>().await.is_ok())
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

#[derive(Clone, Copy)]
enum DetachedChildRuntimeReadiness {
    DirectReady,
    VmMaterialized,
}

impl DetachedChildRuntimeReadiness {
    fn description(self) -> &'static str {
        match self {
            Self::DirectReady => "direct child runtime state",
            Self::VmMaterialized => "vm child runtime state",
        }
    }

    fn ready(self, state_path: &Path) -> Result<bool> {
        match self {
            Self::DirectReady => {
                let state: DirectRuntimeState = read_json(state_path, self.description())?;
                Ok(state.ready)
            }
            Self::VmMaterialized => {
                let _: VmRuntimeState = read_json(state_path, self.description())?;
                Ok(true)
            }
        }
    }
}

async fn wait_for_detached_child_runtime_state(
    pid: u32,
    state_path: &Path,
    timeout: Duration,
    log_path: &Path,
    readiness: DetachedChildRuntimeReadiness,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if state_path.is_file() && readiness.ready(state_path)? {
            return Ok(());
        }
        if !pid_is_alive(pid) {
            let log = fs::read_to_string(log_path).unwrap_or_default();
            return Err(miette::miette!(
                "dynamic child runtime exited before {} became ready\nlog ({}):\n{}",
                readiness.description(),
                log_path.display(),
                log
            ));
        }
        sleep(Duration::from_millis(100)).await;
    }
    let log = fs::read_to_string(log_path).unwrap_or_default();
    Err(miette::miette!(
        "timed out waiting for dynamic {}\nstate ({}):\nlog ({}):\n{}",
        readiness.description(),
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
                    MeshProtocol::Http => {
                        endpoint_returns_http_response_blocking(addr, Duration::from_millis(250))?
                    }
                    MeshProtocol::Tcp => endpoint_accepts_stable_connection_blocking(
                        addr,
                        Duration::from_millis(250),
                    )?,
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
    plan: &SiteControllerRuntimePlan,
    state: &SiteControllerRuntimeState,
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
    plan: &SiteControllerRuntimePlan,
    children: &[SiteControllerRuntimeChildRecord],
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
            &site_controller_runtime_child_runtime_root(plan, child.child_id),
        )?);
    }
    Ok(peers)
}

fn local_direct_peer_identities(
    plan: &SiteControllerRuntimePlan,
    state: &SiteControllerRuntimeState,
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
    plan: &SiteControllerRuntimePlan,
    children: &[SiteControllerRuntimeChildRecord],
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
            &site_controller_runtime_child_runtime_root(plan, child.child_id),
        )?);
    }
    Ok(peers)
}

fn direct_peer_ports_for_artifact(
    artifact_root: &Path,
    runtime_root: &Path,
) -> Result<BTreeMap<String, u16>> {
    let plan: DirectPlan = read_json(&artifact_root.join("direct-plan.json"), "direct plan")?;
    let mut peers = BTreeMap::new();
    for component in &plan.components {
        let config: MeshConfigPublic = read_json(
            &runtime_root.join(&component.sidecar.mesh_config_path),
            "mesh config",
        )?;
        peers.insert(config.identity.id, config.mesh_listen.port());
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
    plan: &SiteControllerRuntimePlan,
    state: &SiteControllerRuntimeState,
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
    plan: &SiteControllerRuntimePlan,
    children: &[SiteControllerRuntimeChildRecord],
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
            &site_controller_runtime_child_runtime_root(plan, child.child_id),
        )?);
    }
    Ok(peers)
}

fn local_vm_peer_identities(
    plan: &SiteControllerRuntimePlan,
    state: &SiteControllerRuntimeState,
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
    plan: &SiteControllerRuntimePlan,
    children: &[SiteControllerRuntimeChildRecord],
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
            &site_controller_runtime_child_runtime_root(plan, child.child_id),
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

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    static VM_ACCEL_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    #[test]
    fn kubernetes_router_ready_prefers_local_targets_over_manager_state() {
        let plan = SiteControllerRuntimePlan {
            schema: "amber.run.site_controller_runtime_plan".to_string(),
            version: 1,
            run_id: "run".to_string(),
            mesh_scope: "scope".to_string(),
            run_root: "/tmp/run".to_string(),
            site_id: "kind_local".to_string(),
            kind: SiteKind::Kubernetes,
            router_identity_id: "/site/test/router".to_string(),
            local_router_control: Some("amber-router:24100".to_string()),
            artifact_dir: "/tmp/artifact".to_string(),
            site_state_root: "/tmp/state".to_string(),
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 4100)),
            storage_root: None,
            runtime_root: None,
            router_mesh_port: Some(24000),
            compose_project: None,
            kubernetes_namespace: Some("ns".to_string()),
            context: None,
            observability_endpoint: None,
            vm_endpoint_forward_ready_timeout_secs: None,
            launch_env: BTreeMap::new(),
        };
        let stale_manager_state = SiteManagerState {
            schema: SITE_PLAN_SCHEMA.to_string(),
            version: SITE_PLAN_VERSION,
            run_id: "run".to_string(),
            site_id: "kind_local".to_string(),
            kind: SiteKind::Kubernetes,
            status: SiteLifecycleStatus::Running,
            artifact_dir: "/tmp/artifact".to_string(),
            supervisor_pid: 1,
            process_pid: None,
            compose_project: None,
            kubernetes_namespace: Some("ns".to_string()),
            port_forward_pid: None,
            context: None,
            router_control: Some("127.0.0.1:9".to_string()),
            router_mesh_addr: Some("127.0.0.1:9".to_string()),
            compose_consumer_router_mesh_addr: None,
            kubernetes_consumer_router_mesh_addr: None,
            router_identity_id: None,
            router_public_key_b64: None,
            site_controller_url: None,
            last_error: None,
        };

        assert_eq!(
            kubernetes_router_ready_targets(&plan, Some(&stale_manager_state))
                .expect("targets should resolve"),
            Some((
                "amber-router:24100".to_string(),
                "amber-router:24000".to_string()
            )),
            "embedded kubernetes controllers must prefer their local router service over stale \
             manager-state loopback endpoints",
        );
    }

    #[test]
    fn kubernetes_router_ready_falls_back_to_manager_state_when_local_target_is_absent() {
        let plan = SiteControllerRuntimePlan {
            schema: "amber.run.site_controller_runtime_plan".to_string(),
            version: 1,
            run_id: "run".to_string(),
            mesh_scope: "scope".to_string(),
            run_root: "/tmp/run".to_string(),
            site_id: "kind_local".to_string(),
            kind: SiteKind::Kubernetes,
            router_identity_id: "/site/test/router".to_string(),
            local_router_control: None,
            artifact_dir: "/tmp/artifact".to_string(),
            site_state_root: "/tmp/state".to_string(),
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 4100)),
            storage_root: None,
            runtime_root: None,
            router_mesh_port: Some(24000),
            compose_project: None,
            kubernetes_namespace: Some("ns".to_string()),
            context: None,
            observability_endpoint: None,
            vm_endpoint_forward_ready_timeout_secs: None,
            launch_env: BTreeMap::new(),
        };
        let manager_state = SiteManagerState {
            schema: SITE_PLAN_SCHEMA.to_string(),
            version: SITE_PLAN_VERSION,
            run_id: "run".to_string(),
            site_id: "kind_local".to_string(),
            kind: SiteKind::Kubernetes,
            status: SiteLifecycleStatus::Running,
            artifact_dir: "/tmp/artifact".to_string(),
            supervisor_pid: 1,
            process_pid: None,
            compose_project: None,
            kubernetes_namespace: Some("ns".to_string()),
            port_forward_pid: None,
            context: None,
            router_control: Some("127.0.0.1:24100".to_string()),
            router_mesh_addr: Some("127.0.0.1:24000".to_string()),
            compose_consumer_router_mesh_addr: None,
            kubernetes_consumer_router_mesh_addr: None,
            router_identity_id: None,
            router_public_key_b64: None,
            site_controller_url: None,
            last_error: None,
        };

        assert_eq!(
            kubernetes_router_ready_targets(&plan, Some(&manager_state))
                .expect("targets should resolve"),
            Some(("127.0.0.1:24100".to_string(), "127.0.0.1:24000".to_string())),
            "host-supervised kubernetes sites should still fall back to manager-state endpoints \
             when no embedded local router target is available",
        );
    }

    #[test]
    fn vm_endpoint_forward_ready_timeout_honors_forced_tcg() {
        let _guard = VM_ACCEL_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock should not be poisoned");
        let previous = env::var_os("AMBER_VM_FORCE_TCG");
        unsafe {
            env::set_var("AMBER_VM_FORCE_TCG", "1");
        }
        assert_eq!(
            vm_endpoint_forward_ready_timeout(),
            TCG_VM_STARTUP_TIMEOUT,
            "forced TCG must extend VM readiness timeouts on every supported host platform",
        );
        match previous {
            Some(value) => unsafe { env::set_var("AMBER_VM_FORCE_TCG", value) },
            None => unsafe { env::remove_var("AMBER_VM_FORCE_TCG") },
        }
    }

    #[test]
    fn runtime_plan_vm_ready_timeout_uses_explicit_budget() {
        let plan = SiteControllerRuntimePlan {
            schema: "amber.run.site_controller_runtime_plan".to_string(),
            version: 1,
            run_id: "run".to_string(),
            mesh_scope: "scope".to_string(),
            run_root: "/tmp/run".to_string(),
            site_id: "vm_local".to_string(),
            kind: SiteKind::Vm,
            router_identity_id: "/site/vm_local/router".to_string(),
            local_router_control: None,
            artifact_dir: "/tmp/artifact".to_string(),
            site_state_root: "/tmp/state".to_string(),
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 4100)),
            storage_root: None,
            runtime_root: None,
            router_mesh_port: Some(24000),
            compose_project: None,
            kubernetes_namespace: None,
            context: None,
            observability_endpoint: None,
            vm_endpoint_forward_ready_timeout_secs: Some(721),
            launch_env: BTreeMap::new(),
        };

        assert_eq!(
            vm_endpoint_forward_ready_timeout_for_runtime_plan(&plan),
            Duration::from_secs(721),
            "dynamic VM child publication should consume the budget written into the runtime plan",
        );
    }

    #[tokio::test]
    async fn detached_direct_child_runtime_state_waits_for_ready_flag() {
        let temp = tempfile::tempdir().expect("temp dir should be created");
        let state_path = temp.path().join("direct-runtime.json");
        let log_path = temp.path().join("site.log");
        write_json(
            &state_path,
            &DirectRuntimeState {
                ready: false,
                ..Default::default()
            },
        )
        .expect("direct runtime state should write");

        let err = wait_for_detached_child_runtime_state(
            std::process::id(),
            &state_path,
            Duration::from_millis(1),
            &log_path,
            DetachedChildRuntimeReadiness::DirectReady,
        )
        .await
        .expect_err("not-ready direct runtime state should time out");
        assert!(
            err.to_string().contains("direct child runtime state"),
            "error should identify the direct child runtime state: {err}"
        );

        write_json(
            &state_path,
            &DirectRuntimeState {
                ready: true,
                ..Default::default()
            },
        )
        .expect("direct runtime state should write");
        wait_for_detached_child_runtime_state(
            std::process::id(),
            &state_path,
            Duration::from_secs(1),
            &log_path,
            DetachedChildRuntimeReadiness::DirectReady,
        )
        .await
        .expect("ready direct runtime state should be accepted");
    }

    #[tokio::test]
    async fn detached_vm_child_runtime_state_accepts_materialized_vm_state() {
        let temp = tempfile::tempdir().expect("temp dir should be created");
        let state_path = temp.path().join("vm-runtime.json");
        let log_path = temp.path().join("site.log");
        write_json(
            &state_path,
            &VmRuntimeState {
                router_mesh_port: Some(23000),
                ..Default::default()
            },
        )
        .expect("vm runtime state should write");

        wait_for_detached_child_runtime_state(
            std::process::id(),
            &state_path,
            Duration::from_secs(1),
            &log_path,
            DetachedChildRuntimeReadiness::VmMaterialized,
        )
        .await
        .expect("materialized VM runtime state should be accepted");
    }
}
