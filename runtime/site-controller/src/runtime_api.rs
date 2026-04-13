use std::{
    collections::BTreeMap,
    future::Future,
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
};

use amber_compiler::run_plan::{RunLink, SiteKind};
use amber_mesh::{InboundRoute, MeshConfigPublic, MeshIdentityPublic, MeshPeer};
use amber_proxy::ControlEndpoint;
use base64::Engine as _;
use miette::{IntoDiagnostic as _, Result, WrapErr as _};
use serde::{Deserialize, Serialize};

use super::state::{FrameworkControlState, LiveChildRecord, SiteControllerPlan};

const KUBERNETES_MESH_PROVISION_CONFIGMAP_PATH: &str = "01-configmaps/amber-mesh-provision.yaml";
const KUBERNETES_PROVISIONER_JOB_PATH: &str = "02-rbac/amber-provisioner-job.yaml";
const KUBERNETES_PROVISIONER_ROLE_PATH: &str = "02-rbac/amber-provisioner-role.yaml";
const KUBERNETES_PROVISIONER_ROLEBINDING_PATH: &str = "02-rbac/amber-provisioner-rolebinding.yaml";
const KUBERNETES_PROVISIONER_SERVICE_ACCOUNT_PATH: &str = "02-rbac/amber-provisioner-sa.yaml";
const KUBERNETES_ROUTER_EXTERNAL_SECRET_NAME: &str = "amber-router-external";
const SITE_CONTROLLER_RUNTIME_PLAN_SCHEMA: &str = "amber.run.site_controller_runtime_plan";
const SITE_CONTROLLER_RUNTIME_PLAN_VERSION: u32 = 1;

pub type SiteControllerRuntimeFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

pub(crate) trait SiteControllerRuntime: Send + Sync {
    fn cleanup<'a>(&'a self) -> SiteControllerRuntimeFuture<'a, ()>;

    fn resolve_link_external_url<'a>(
        &'a self,
        provider: &'a LaunchedSite,
        provider_output_dir: &'a Path,
        link: &'a RunLink,
        consumer_kind: SiteKind,
        run_root: &'a Path,
    ) -> SiteControllerRuntimeFuture<'a, String>;

    fn prepare_child<'a>(
        &'a self,
        plan: &'a SiteControllerPlan,
        state: FrameworkControlState,
        child: LiveChildRecord,
    ) -> SiteControllerRuntimeFuture<'a, ()>;

    fn publish_child<'a>(
        &'a self,
        plan: &'a SiteControllerPlan,
        state: FrameworkControlState,
        child: LiveChildRecord,
    ) -> SiteControllerRuntimeFuture<'a, ()>;

    fn rollback_child<'a>(
        &'a self,
        plan: &'a SiteControllerPlan,
        child_id: u64,
    ) -> SiteControllerRuntimeFuture<'a, ()>;

    fn destroy_child<'a>(
        &'a self,
        plan: &'a SiteControllerPlan,
        state: FrameworkControlState,
        child: LiveChildRecord,
    ) -> SiteControllerRuntimeFuture<'a, ()>;

    fn collect_live_component_runtime_metadata(
        &self,
        plan: &SiteControllerRuntimePlan,
    ) -> Result<BTreeMap<String, LiveComponentRuntimeMetadata>>;

    fn load_live_site_router_mesh_config(
        &self,
        plan: &SiteControllerRuntimePlan,
    ) -> Result<MeshConfigPublic>;

    fn router_mesh_addr_for_consumer(
        &self,
        provider_kind: SiteKind,
        consumer_kind: SiteKind,
        router_mesh_addr: &str,
    ) -> Result<String>;

    fn update_desired_overlay_for_consumer(
        &self,
        site_state_root: &Path,
        overlay_id: &str,
        overlay: DesiredExternalSlotOverlay,
    ) -> Result<()>;

    fn update_desired_overlay_for_provider(
        &self,
        site_state_root: &Path,
        overlay_id: &str,
        overlay: DesiredExportPeerOverlay,
    ) -> Result<()>;

    fn clear_desired_overlay_for_consumer(
        &self,
        site_state_root: &Path,
        overlay_id: &str,
    ) -> Result<()>;

    fn clear_desired_overlay_for_provider(
        &self,
        site_state_root: &Path,
        overlay_id: &str,
    ) -> Result<()>;
}

pub(crate) type SharedSiteControllerRuntime = Arc<dyn SiteControllerRuntime>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SiteReceipt {
    pub kind: SiteKind,
    pub artifact_dir: String,
    pub supervisor_pid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compose_project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes_namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_forward_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router_control: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router_mesh_addr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router_identity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router_public_key_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site_controller_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site_controller_url: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SiteControllerRuntimePlan {
    pub schema: String,
    pub version: u32,
    pub run_id: String,
    pub mesh_scope: String,
    pub run_root: String,
    pub site_id: String,
    pub kind: SiteKind,
    pub router_identity_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_router_control: Option<String>,
    pub artifact_dir: String,
    pub site_state_root: String,
    pub listen_addr: SocketAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router_mesh_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compose_project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes_namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observability_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub launch_env: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct LiveComponentRuntimeMetadata {
    pub moniker: String,
    pub host_mesh_addr: String,
    pub control_endpoint: Option<ControlEndpoint>,
    pub mesh_config: MeshConfigPublic,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredExternalSlotOverlay {
    pub slot_name: String,
    pub url: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredExportPeerOverlay {
    pub export_name: String,
    pub peer_id: String,
    pub peer_key_b64: String,
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DesiredRouteOverlay {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<MeshPeer>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbound_routes: Vec<InboundRoute>,
}

#[derive(Clone, Debug)]
pub struct LaunchedSite {
    pub receipt: SiteReceipt,
    pub router_control: ControlEndpoint,
    pub router_identity: MeshIdentityPublic,
    pub router_addr: SocketAddr,
}

pub fn site_controller_runtime_plan_from_controller_plan(
    plan: &SiteControllerPlan,
) -> SiteControllerRuntimePlan {
    SiteControllerRuntimePlan {
        schema: SITE_CONTROLLER_RUNTIME_PLAN_SCHEMA.to_string(),
        version: SITE_CONTROLLER_RUNTIME_PLAN_VERSION,
        run_id: plan.run_id.clone(),
        mesh_scope: plan.mesh_scope.clone(),
        run_root: plan.run_root.clone(),
        site_id: plan.site_id.clone(),
        kind: plan.kind,
        router_identity_id: plan.router_identity_id.clone(),
        local_router_control: plan.local_router_control.clone(),
        artifact_dir: plan.artifact_dir.clone(),
        site_state_root: plan.site_state_root.clone(),
        listen_addr: plan.listen_addr,
        storage_root: plan.storage_root.clone(),
        runtime_root: plan.runtime_root.clone(),
        router_mesh_port: plan.router_mesh_port,
        compose_project: plan.compose_project.clone(),
        kubernetes_namespace: plan.kubernetes_namespace.clone(),
        context: plan.context.clone(),
        observability_endpoint: plan.observability_endpoint.clone(),
        launch_env: plan.launch_env.clone(),
    }
}

pub fn site_controller_runtime_child_root_for_site(
    site_state_root: &Path,
    child_id: u64,
) -> PathBuf {
    site_state_root
        .join("framework-component")
        .join("children")
        .join(child_id.to_string())
}

pub fn site_state_path(state_root: &Path, site_id: &str) -> PathBuf {
    state_root.join(site_id).join("manager-state.json")
}

pub fn site_controller_plan_path(site_state_root: &Path) -> PathBuf {
    site_state_root.join("site-controller-plan.json")
}

fn yaml_string(value: &str) -> serde_yaml::Value {
    serde_yaml::Value::String(value.to_string())
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
    child_component_labels: &std::collections::BTreeSet<String>,
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

pub fn project_kubernetes_dynamic_child_artifact_files(
    artifact_files: &BTreeMap<String, String>,
    component_ids: &[usize],
) -> Result<BTreeMap<String, String>> {
    let child_component_labels = component_ids
        .iter()
        .map(|component_id| format!("c{component_id}"))
        .collect::<std::collections::BTreeSet<_>>();
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
    let mut kept_resource_names = std::collections::BTreeSet::new();
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

pub fn parse_control_endpoint(raw: &str) -> Result<ControlEndpoint> {
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

pub fn decode_public_key(value: &str) -> Result<[u8; 32]> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .into_diagnostic()
        .wrap_err("invalid base64 router public key")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| miette::miette!("invalid router public key length"))
}

pub fn launched_site_from_receipt(
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
