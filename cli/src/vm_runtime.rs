use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    env,
    fmt::Write as _,
    fs::{self, File},
    hash::{Hash as _, Hasher as _},
    io::{Seek as _, SeekFrom, Write as _},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, ExitStatus, Stdio},
};

use amber_compiler::reporter::{
    direct::{DirectRuntimeAddressPlan, DirectRuntimeConfigPayload, DirectRuntimeUrlSource},
    vm::{
        VM_PLAN_VERSION, VM_RUNTIME_SLOT_HOST, VmComponentPlan, VmEgressPlan, VmHostPathPart,
        VmHostPathPlan, VmPlan, VmRouterPlan, VmScalarPlanU32, VmTemplateStringPlan,
    },
};
use amber_config::{
    env_var_for_path, get_by_path_opt, render_mount_specs, render_template_string_with_context,
    resolve_runtime_component_config,
};
use amber_mesh::{
    InboundTarget, MESH_CONFIG_FILENAME, MESH_PROVISION_PLAN_VERSION, MeshConfigPublic,
    MeshIdentityPublic, MeshProtocol, MeshProvisionPlan,
};
use amber_template::{
    ConfigTemplatePayload, MountSpec, RuntimeSlotObject, RuntimeTemplateContext, TemplatePart,
};
use base64::Engine as _;
use fatfs::{FileSystem, FormatVolumeOptions, FsOptions, format_volume};
use miette::{Context as _, IntoDiagnostic as _, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{
    io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    net::UnixStream,
    process::Command as TokioCommand,
    time::{Duration, Instant, sleep, timeout},
};

use crate::{
    cross_site_router_mesh_bind_ip, read_existing_peer_identities,
    tcp_readiness::{
        endpoint_accepts_stable_connection, endpoint_returns_http_response,
        wait_for_stable_endpoint,
    },
};
mod artifacts;
mod preview;
mod state;

use self::{artifacts::*, preview::*, state::*};
pub(crate) use self::{
    preview::build_vm_site_launch_preview,
    state::{
        ensure_control_socket_link, vm_current_control_socket_path,
        vm_endpoint_forward_ready_timeout, write_vm_runtime_state,
    },
};

const VM_CHILD_POLL_INTERVAL: Duration = Duration::from_millis(150);
const VM_SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(15);
const VM_QMP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);
pub(crate) const TCG_VM_STARTUP_TIMEOUT: Duration = Duration::from_secs(720);

const VM_RUNTIME_DISK_LABEL: [u8; 11] = *b"AMBERRUN   ";
const VM_RUNTIME_DISK_SIZE: u64 = 64 * 1024 * 1024;
pub(crate) const VM_HOST_GUESTFWD_IP: &str = "10.0.2.100";
const QEMU_VIRTIO_NET_DEVICE: &str = "virtio-net-pci,netdev=net0,rombar=0";

const MANAGED_PROCESS_PATH: &str = "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/\
                                    local/sbin:/usr/bin:/bin:/usr/sbin:/sbin";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct VmRuntimeState {
    #[serde(default)]
    pub(crate) slot_ports_by_component: BTreeMap<usize, BTreeMap<String, u16>>,
    #[serde(default)]
    pub(crate) slot_route_ports_by_component: BTreeMap<usize, BTreeMap<String, Vec<u16>>>,
    #[serde(default)]
    pub(crate) route_host_ports_by_component: BTreeMap<usize, BTreeMap<String, Vec<u16>>>,
    #[serde(default)]
    pub(crate) endpoint_forwards_by_component: BTreeMap<usize, BTreeMap<u16, u16>>,
    #[serde(default)]
    pub(crate) component_mesh_port_by_id: BTreeMap<usize, u16>,
    #[serde(default)]
    pub(crate) router_mesh_port: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VmControlSocketPaths {
    artifact_link: PathBuf,
    current_link: PathBuf,
    runtime: PathBuf,
}

#[derive(Debug)]
struct ManagedChild {
    name: String,
    shutdown: ManagedChildShutdown,
    child: tokio::process::Child,
}

#[derive(Clone, Debug)]
enum ManagedChildShutdown {
    Signal,
    Qemu { qmp_socket: PathBuf },
}

#[derive(Clone, Debug)]
struct VmPortAssignments {
    state: VmRuntimeState,
    route_host_ports_by_component: BTreeMap<usize, BTreeMap<String, Vec<u16>>>,
}

#[derive(Clone, Debug)]
struct VmLaunchPlan {
    name: String,
    command: Vec<String>,
    qmp_socket: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct VmPersistentDiskPreview {
    pub(crate) serial: String,
    pub(crate) mount_path: String,
    pub(crate) host_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct VmLaunchPreviewIssue {
    pub(crate) field: String,
    pub(crate) detail: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct VmLaunchPreview {
    pub(crate) name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) command: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) base_image: Option<String>,
    pub(crate) overlay_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) runtime_disk_path: Option<String>,
    pub(crate) seed_disk_path: String,
    pub(crate) qmp_socket: String,
    pub(crate) serial_log: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cpus: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) memory_mib: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) persistent_disks: Vec<VmPersistentDiskPreview>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) unresolved_fields: Vec<VmLaunchPreviewIssue>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct VmSiteLaunchPreview {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) router_public_key_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) virtual_machines: Vec<VmLaunchPreview>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) inspectability_warnings: Vec<String>,
}

#[derive(Clone, Copy, Debug)]
struct VmHostContext<'a> {
    runtime_root: &'a Path,
    storage_root: &'a Path,
    qemu_img: &'a Path,
    qemu_system: &'a Path,
    amber_cli: &'a str,
    arch: VmArch,
    accel: QemuAccel,
}

#[derive(Clone, Debug)]
struct RenderedMountFile {
    guest_path: String,
    contents: String,
}

#[derive(Clone, Debug)]
struct RuntimeDiskFile {
    path: String,
    contents: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeExitReason {
    CtrlC,
    ChildExited,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VmArch {
    Aarch64,
    X86_64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QemuAccel {
    #[cfg(target_os = "macos")]
    Hvf,
    #[cfg(target_os = "linux")]
    Kvm,
    Tcg,
}

#[derive(Debug, Deserialize)]
struct QemuImgInfo {
    format: String,
}

struct VmRuntimeInputs {
    plan_root: PathBuf,
    vm_plan: VmPlan,
    mesh_plan: MeshProvisionPlan,
}

#[derive(Clone, Debug, Default)]
struct VmPreviewComponentConfig {
    config: Option<Value>,
    schema: Option<Value>,
    error: Option<String>,
}

#[derive(Clone, Debug)]
struct VmLaunchArtifacts {
    vm_root: PathBuf,
    overlay_path: PathBuf,
    runtime_disk_path: Option<PathBuf>,
    seed_disk_path: PathBuf,
    qmp_socket: PathBuf,
    serial_log: PathBuf,
    persistent_disks: Vec<VmPersistentDiskArtifact>,
}

#[derive(Clone, Debug)]
struct VmPersistentDiskArtifact {
    serial: String,
    mount_path: String,
    host_path: PathBuf,
}

pub(crate) async fn run_vm_init(
    plan: PathBuf,
    storage_root: Option<PathBuf>,
    runtime_root: Option<PathBuf>,
    router_mesh_port: Option<u16>,
    existing_peer_ports: Option<PathBuf>,
    existing_peer_identities: Option<PathBuf>,
    skip_router: bool,
) -> Result<()> {
    let plan_path = canonicalize_path(&plan, "vm plan")?;
    let VmRuntimeInputs {
        plan_root,
        vm_plan,
        mesh_plan,
    } = load_vm_runtime_inputs(&plan_path)?;
    let storage_root = vm_storage_root(&plan_root, storage_root.as_deref())
        .into_diagnostic()
        .wrap_err("failed to resolve vm storage root")?;

    let runtime_dir = if let Some(runtime_root) = runtime_root.as_ref() {
        fs::create_dir_all(runtime_root)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "failed to create vm runtime workspace {}",
                    runtime_root.display()
                )
            })?;
        None
    } else {
        Some(
            tempfile::Builder::new()
                .prefix("amber-vm-")
                .tempdir()
                .into_diagnostic()
                .wrap_err("failed to create vm runtime workspace")?,
        )
    };
    let runtime_root = runtime_dir
        .as_ref()
        .map(|dir| dir.path().to_path_buf())
        .or(runtime_root)
        .expect("runtime root should be available");
    let runtime_state_path = vm_runtime_state_path(&plan_root);
    let mut children = Vec::<ManagedChild>::new();
    let mut log_tasks = Vec::new();
    let mut control_socket_paths = None;
    let reuse_materialized_runtime = runtime_dir.is_none() && runtime_state_path.is_file();
    let existing_peer_ports_by_id =
        read_existing_peer_ports(existing_peer_ports.as_deref(), "vm existing peer ports")?;
    let existing_peer_identities_by_id = read_existing_peer_identities(
        existing_peer_identities.as_deref(),
        "vm existing peer identities",
    )?;

    let supervision = async {
        let port_assignments = if skip_router || !existing_peer_ports_by_id.is_empty() {
            materialize_vm_runtime_with_existing(
                &plan_root,
                &runtime_root,
                &vm_plan,
                &mesh_plan,
                router_mesh_port,
                VmExistingMeshState {
                    reuse_existing: reuse_materialized_runtime,
                    peer_ports_by_id: &existing_peer_ports_by_id,
                    peer_identities_by_id: &existing_peer_identities_by_id,
                },
            )?
        } else {
            materialize_vm_runtime(
                &plan_root,
                &runtime_root,
                &vm_plan,
                &mesh_plan,
                router_mesh_port,
                reuse_materialized_runtime,
            )?
        };
        project_existing_vm_peer_identities(
            &runtime_root,
            &vm_plan,
            &existing_peer_identities_by_id,
        )?;

        let router_binary = resolve_host_binary("amber-router")?;
        if !skip_router && let Some(router) = vm_plan.router.as_ref() {
            control_socket_paths = Some(
                spawn_vm_router(
                    &router_binary,
                    &runtime_root,
                    &plan_root,
                    router,
                    &mut children,
                    &mut log_tasks,
                )
                .await?,
            );
        }

        for component in &vm_plan.components {
            spawn_component_sidecar(
                &router_binary,
                &runtime_root,
                component,
                &mut children,
                &mut log_tasks,
            )
            .await?;
        }

        let components_by_id = vm_plan
            .components
            .iter()
            .map(|component| (component.id, component))
            .collect::<HashMap<_, _>>();

        let qemu_system = resolve_qemu_system_binary()?;
        let qemu_img = resolve_qemu_img_binary()?;
        let amber_cli = resolve_host_binary("amber")?;
        let arch = host_arch()?;
        let accel = detect_qemu_accel();

        for component_id in &vm_plan.startup_order {
            let component = components_by_id.get(component_id).copied().ok_or_else(|| {
                miette::miette!(
                    "vm plan startup order references unknown component id {}",
                    component_id
                )
            })?;

            let runtime_context = build_vm_runtime_template_context(
                &vm_plan.runtime_addresses,
                &port_assignments.state,
            )?;
            let component_config =
                build_component_config(component.runtime_config.as_ref(), &runtime_context)?;
            let mount_files = render_mount_files(
                component.mount_spec_b64.as_deref(),
                component_config.as_ref().map(|(config, _)| config),
                component_config.as_ref().map(|(_, schema)| schema),
                &runtime_context,
            )?;
            wait_for_guestfwd_targets(
                component,
                &port_assignments,
                vm_endpoint_forward_ready_timeout(),
            )?;
            let vm_launch = build_vm_launch_plan(
                VmHostContext {
                    runtime_root: &runtime_root,
                    storage_root: &storage_root,
                    qemu_img: &qemu_img,
                    qemu_system: &qemu_system,
                    amber_cli: &amber_cli,
                    arch,
                    accel,
                },
                component,
                &port_assignments,
                &runtime_context,
                component_config.as_ref().map(|(config, _)| config),
                &mount_files,
            )?;
            spawn_command(
                vm_launch.name,
                vm_launch.command,
                &runtime_root,
                BTreeMap::new(),
                ManagedChildShutdown::Qemu {
                    qmp_socket: vm_launch.qmp_socket,
                },
                &mut children,
                &mut log_tasks,
            )
            .await?;
            let child = children.last_mut().ok_or_else(|| {
                miette::miette!(
                    "missing managed child for vm component {} after launch",
                    component.moniker
                )
            })?;
            wait_for_endpoint_forwards(
                component,
                &runtime_root,
                vm_endpoint_forward_ready_timeout(),
                child,
            )?;
        }
        supervise_children(&mut children).await
    }
    .await;

    cleanup_vm_runtime(
        &mut children,
        log_tasks,
        &runtime_state_path,
        control_socket_paths.as_ref(),
        runtime_dir,
    )
    .await;

    let (reason, exit_code) = supervision?;
    match reason {
        RuntimeExitReason::CtrlC => Ok(()),
        RuntimeExitReason::ChildExited => {
            if exit_code == 0 {
                Ok(())
            } else {
                std::process::exit(exit_code);
            }
        }
    }
}

fn read_existing_peer_ports(
    path: Option<&Path>,
    description: &str,
) -> Result<BTreeMap<String, u16>> {
    let Some(path) = path else {
        return Ok(BTreeMap::new());
    };
    let raw = fs::read_to_string(path)
        .map_err(|err| miette::miette!("failed to read {description} {}: {err}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|err| miette::miette!("invalid {description} {}: {err}", path.display()))
}

fn build_vm_launch_plan(
    host: VmHostContext<'_>,
    component: &VmComponentPlan,
    port_assignments: &VmPortAssignments,
    runtime_context: &RuntimeTemplateContext,
    component_config: Option<&Value>,
    mount_files: &[RenderedMountFile],
) -> Result<VmLaunchPlan> {
    let artifacts = build_vm_launch_artifacts(host, component);
    fs::create_dir_all(&artifacts.vm_root)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create vm runtime directory {}",
                artifacts.vm_root.display()
            )
        })?;

    let base_image = resolve_vm_base_image(&component.base_image, component_config)?;
    create_overlay_image(host.qemu_img, &base_image, &artifacts.overlay_path)?;

    if let Some(runtime_disk_path) = artifacts.runtime_disk_path.as_ref() {
        let runtime_disk_files = build_runtime_disk_files(mount_files)?;
        write_fat_image(
            runtime_disk_path,
            VM_RUNTIME_DISK_SIZE,
            VM_RUNTIME_DISK_LABEL,
            &runtime_disk_files,
        )?;
    }

    let instance_id = format!(
        "amber-{}-{}",
        component.id,
        runtime_root_hash(host.runtime_root)
    );
    let user_data = render_user_data(component, component_config, runtime_context)?;
    let meta_data = format!(
        "instance-id: {instance_id}\nlocal-hostname: {}\n",
        cloud_init_hostname(&component.log_name)
    );
    let vendor_data = render_vm_template_string(
        component.cloud_init_vendor_data.as_ref(),
        component_config,
        runtime_context,
    )?;
    write_cloud_init_seed_image(
        &artifacts.seed_disk_path,
        &user_data,
        &meta_data,
        vendor_data.as_deref(),
    )?;

    for (mount, disk) in component
        .storage_mounts
        .iter()
        .zip(artifacts.persistent_disks.iter())
    {
        ensure_persistent_image(host.qemu_img, &disk.host_path, &mount.size)?;
    }

    let cpus = resolve_vm_scalar(&component.cpus, "program.vm.cpus", component_config)?;
    let memory_mib = resolve_vm_scalar(
        &component.memory_mib,
        "program.vm.memory_mib",
        component_config,
    )?;
    let qmp_socket_dir = artifacts.qmp_socket.parent().ok_or_else(|| {
        miette::miette!(
            "invalid vm qmp socket path {}",
            artifacts.qmp_socket.display()
        )
    })?;
    fs::create_dir_all(qmp_socket_dir)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create vm qmp socket directory {}",
                qmp_socket_dir.display()
            )
        })?;
    if artifacts.qmp_socket.exists() {
        fs::remove_file(&artifacts.qmp_socket)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "failed to remove stale vm qmp socket {}",
                    artifacts.qmp_socket.display()
                )
            })?;
    }
    let command = build_vm_qemu_command(
        host,
        component,
        port_assignments,
        cpus,
        memory_mib,
        &artifacts,
    )?;

    Ok(VmLaunchPlan {
        name: component.log_name.clone(),
        command,
        qmp_socket: artifacts.qmp_socket,
    })
}

fn load_vm_runtime_inputs(plan_path: &Path) -> Result<VmRuntimeInputs> {
    let plan_root = plan_path
        .parent()
        .ok_or_else(|| miette::miette!("invalid vm plan path {}", plan_path.display()))?
        .to_path_buf();
    let vm_plan: VmPlan = read_json_file(plan_path, "vm plan")?;
    if vm_plan.version != VM_PLAN_VERSION {
        return Err(miette::miette!(
            "unsupported vm plan version {} in {}; expected {}",
            vm_plan.version,
            plan_path.display(),
            VM_PLAN_VERSION
        ));
    }
    let mesh_plan_path = plan_root.join(&vm_plan.mesh_provision_plan);
    let mesh_plan: MeshProvisionPlan = read_json_file(&mesh_plan_path, "mesh provision plan")?;
    if mesh_plan.version != MESH_PROVISION_PLAN_VERSION {
        return Err(miette::miette!(
            "unsupported mesh provision plan version {} in {}; expected {}",
            mesh_plan.version,
            mesh_plan_path.display(),
            MESH_PROVISION_PLAN_VERSION
        ));
    }
    Ok(VmRuntimeInputs {
        plan_root,
        vm_plan,
        mesh_plan,
    })
}

fn push_qemu_block_device(
    command: &mut Vec<String>,
    id: &str,
    format: &str,
    path: &Path,
    readonly: bool,
    serial: Option<&str>,
    bootindex: Option<u32>,
) {
    command.push("-drive".to_string());
    command.push(format!(
        "if=none,id={id},format={format},readonly={},file={}",
        if readonly { "on" } else { "off" },
        path.display()
    ));
    command.push("-device".to_string());
    let mut device = format!("virtio-blk-pci,drive={id},rombar=0");
    if let Some(serial) = serial {
        device.push_str(",serial=");
        device.push_str(serial);
    }
    if let Some(bootindex) = bootindex {
        device.push_str(",bootindex=");
        device.push_str(&bootindex.to_string());
    }
    command.push(device);
}

fn runtime_root_hash(runtime_root: &Path) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    runtime_root.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn cloud_init_hostname(log_name: &str) -> String {
    let mut out = String::new();
    for ch in log_name.chars() {
        let ch = ch.to_ascii_lowercase();
        if ch.is_ascii_alphanumeric() || ch == '-' {
            out.push(ch);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_string()
}

fn resolve_vm_scalar(
    plan: &VmScalarPlanU32,
    field_name: &str,
    component_config: Option<&Value>,
) -> Result<u32> {
    let value = match plan {
        VmScalarPlanU32::Literal { value } => *value,
        VmScalarPlanU32::RuntimeConfig { query } => {
            let component_config = component_config.ok_or_else(|| {
                miette::miette!(
                    "{field_name} references config path {}, but no runtime component config was \
                     provided",
                    query
                )
            })?;
            let value = get_by_path_opt(component_config, query)
                .map_err(|err| {
                    miette::miette!("failed to read {field_name} config path {}: {err}", query)
                })?
                .ok_or_else(|| {
                    miette::miette!(
                        "{field_name} references config path {}, but that path is missing at \
                         runtime",
                        query
                    )
                })?;
            let Some(value) = value.as_u64() else {
                return Err(miette::miette!(
                    "{field_name} expected an unsigned integer at config.{}, got {}",
                    query,
                    value
                ));
            };
            if value > u32::MAX as u64 {
                return Err(miette::miette!(
                    "{field_name} must fit in a 32-bit unsigned integer"
                ));
            }
            value as u32
        }
    };
    if value == 0 {
        return Err(miette::miette!("{field_name} must be greater than zero"));
    }
    Ok(value)
}

fn resolve_vm_base_image(
    plan: &VmHostPathPlan,
    component_config: Option<&Value>,
) -> Result<PathBuf> {
    let raw_path = match plan {
        VmHostPathPlan::Static { path } => path.clone(),
        VmHostPathPlan::RuntimeConfig { query, source_dir } => {
            let path = resolve_vm_runtime_config(component_config, query, "program.vm.image")?;
            return resolve_vm_runtime_host_path(&path, source_dir.as_deref());
        }
        VmHostPathPlan::RuntimeTemplate { parts, source_dir } => {
            let rendered =
                render_vm_host_path_template(parts, component_config, "program.vm.image")?;
            return resolve_vm_runtime_host_path(&rendered, source_dir.as_deref());
        }
    };
    resolve_vm_runtime_host_path(&raw_path, None)
}

fn render_vm_host_path_template(
    parts: &[VmHostPathPart],
    component_config: Option<&Value>,
    field_name: &str,
) -> Result<String> {
    let mut rendered = String::new();
    for part in parts {
        match part {
            VmHostPathPart::Literal { value } => rendered.push_str(value),
            VmHostPathPart::RuntimeConfig { query } => {
                rendered.push_str(&resolve_vm_runtime_config(
                    component_config,
                    query,
                    field_name,
                )?);
            }
        }
    }
    Ok(rendered)
}

fn resolve_vm_runtime_config(
    component_config: Option<&Value>,
    query: &str,
    field_name: &str,
) -> Result<String> {
    let component_config = component_config.ok_or_else(|| {
        miette::miette!(
            "{field_name} references config path {}, but no runtime component config was provided",
            query
        )
    })?;
    let value = get_by_path_opt(component_config, query)
        .map_err(|err| miette::miette!("failed to read {field_name} config path {}: {err}", query))?
        .ok_or_else(|| {
            miette::miette!(
                "{field_name} references config path {}, but that path is missing at runtime",
                query
            )
        })?;
    amber_config::stringify_for_interpolation(value)
        .map_err(|err| miette::miette!("failed to render config.{} for {field_name}: {err}", query))
}

fn resolve_vm_runtime_host_path(raw_path: &str, source_dir: Option<&str>) -> Result<PathBuf> {
    let raw_path = raw_path.trim();
    let mut path = PathBuf::from(raw_path);
    if !path.is_absolute() {
        let Some(source_dir) = source_dir else {
            return Err(miette::miette!(
                "vm base image path must be absolute at runtime: {}",
                path.display()
            ));
        };
        let source_dir = Path::new(source_dir);
        if !source_dir.is_absolute() {
            return Err(miette::miette!(
                "vm base image source directory must be absolute: {}",
                source_dir.display()
            ));
        }
        path = source_dir.join(path);
    }
    if !path.is_file() {
        return Err(miette::miette!(
            "vm base image not found: {}",
            path.display()
        ));
    }
    Ok(path)
}

pub(crate) fn vm_uses_tcg_accel() -> bool {
    matches!(detect_qemu_accel(), QemuAccel::Tcg)
}

fn detect_qemu_accel() -> QemuAccel {
    #[cfg(target_os = "macos")]
    {
        if env::var_os("AMBER_VM_FORCE_TCG").is_some() {
            QemuAccel::Tcg
        } else {
            QemuAccel::Hvf
        }
    }

    #[cfg(target_os = "linux")]
    {
        if env::var_os("AMBER_VM_FORCE_TCG").is_some() {
            QemuAccel::Tcg
        } else if Path::new("/dev/kvm").exists() {
            QemuAccel::Kvm
        } else {
            QemuAccel::Tcg
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        QemuAccel::Tcg
    }
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    let path_var = env::var_os("PATH")?;
    for path in env::split_paths(&path_var) {
        let candidate = path.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

async fn spawn_command(
    name: String,
    command: Vec<String>,
    work_dir: &Path,
    env_map: BTreeMap<String, String>,
    shutdown: ManagedChildShutdown,
    children: &mut Vec<ManagedChild>,
    log_tasks: &mut Vec<tokio::task::JoinHandle<()>>,
) -> Result<u32> {
    let (program, args) = split_command(command)?;
    let mut process = TokioCommand::new(program);
    process.args(args);
    process.current_dir(work_dir);
    configure_command_env(&mut process, work_dir, &env_map);
    #[cfg(unix)]
    unsafe {
        process.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    process.stdout(Stdio::piped());
    process.stderr(Stdio::piped());
    let mut child = process
        .spawn()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to spawn process {name}"))?;
    let pid = child
        .id()
        .ok_or_else(|| miette::miette!("failed to capture process id for {name}"))?;
    if let Some(stdout) = child.stdout.take() {
        let name = name.clone();
        log_tasks.push(tokio::spawn(async move {
            stream_logs(stdout, name, false).await;
        }));
    }
    if let Some(stderr) = child.stderr.take() {
        let name = name.clone();
        log_tasks.push(tokio::spawn(async move {
            stream_logs(stderr, name, true).await;
        }));
    }
    children.push(ManagedChild {
        name,
        shutdown,
        child,
    });
    Ok(pid)
}

fn split_command(command: Vec<String>) -> Result<(String, Vec<String>)> {
    let mut iter = command.into_iter();
    let program = iter
        .next()
        .ok_or_else(|| miette::miette!("command must not be empty"))?;
    Ok((program, iter.collect()))
}

fn configure_command_env(
    command: &mut TokioCommand,
    work_dir: &Path,
    extra_env: &BTreeMap<String, String>,
) {
    command.env_clear();
    command.env("PATH", MANAGED_PROCESS_PATH);
    command.env("HOME", work_dir);
    command.env("TMPDIR", "/tmp");
    command.envs(extra_env);
}

async fn stream_logs<R>(reader: R, name: String, stderr: bool)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = BufReader::new(reader).lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                if stderr {
                    eprintln!("[{name}] {line}");
                } else {
                    println!("[{name}] {line}");
                }
            }
            Ok(None) => break,
            Err(err) => {
                eprintln!("[{name}] log stream error: {err}");
                break;
            }
        }
    }
}

async fn supervise_children(children: &mut [ManagedChild]) -> Result<(RuntimeExitReason, i32)> {
    let mut shutdown = std::pin::pin!(wait_for_shutdown_signal());
    loop {
        tokio::select! {
            res = &mut shutdown => {
                res?;
                return Ok((RuntimeExitReason::CtrlC, 0));
            }
            _ = sleep(VM_CHILD_POLL_INTERVAL) => {
                for child in children.iter_mut() {
                    if let Some(status) = child.child.try_wait().into_diagnostic()? {
                        let exit_code = normalize_exit_code(status);
                        if exit_code != 0 {
                            eprintln!(
                                "vm runtime stopped because {} exited (status: {}, exit code: {})",
                                child.name,
                                status,
                                exit_code
                            );
                        }
                        return Ok((RuntimeExitReason::ChildExited, exit_code));
                    }
                }
            }
        }
    }
}

fn normalize_exit_code(status: ExitStatus) -> i32 {
    if status.success() {
        0
    } else {
        status.code().unwrap_or(1).max(1)
    }
}

async fn wait_for_shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm = signal(SignalKind::terminate())
            .into_diagnostic()
            .wrap_err("failed to install SIGTERM handler")?;
        let mut sighup = signal(SignalKind::hangup())
            .into_diagnostic()
            .wrap_err("failed to install SIGHUP handler")?;

        tokio::select! {
            res = tokio::signal::ctrl_c() => {
                res.into_diagnostic().wrap_err("failed to install Ctrl+C handler")?;
            }
            _ = sigterm.recv() => {}
            _ = sighup.recv() => {}
        }
        Ok(())
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .into_diagnostic()
            .wrap_err("failed to install Ctrl+C handler")?;
        Ok(())
    }
}

async fn terminate_children(children: &mut [ManagedChild]) {
    for child in children.iter_mut() {
        if child.child.try_wait().ok().flatten().is_some() {
            continue;
        }
        match &child.shutdown {
            ManagedChildShutdown::Signal => {
                #[cfg(unix)]
                if let Some(pid) = child.child.id() {
                    let _ = send_sigterm(pid);
                }
                #[cfg(not(unix))]
                {
                    let _ = child.child.start_kill();
                }
            }
            ManagedChildShutdown::Qemu { qmp_socket } => {
                if let Err(err) = send_qemu_powerdown(qmp_socket).await {
                    eprintln!(
                        "failed to request graceful shutdown for {} via {}: {err}",
                        child.name,
                        qmp_socket.display()
                    );
                }
            }
        }
    }

    let deadline = Instant::now() + VM_SHUTDOWN_GRACE_PERIOD;
    loop {
        let mut all_exited = true;
        for child in children.iter_mut() {
            if child.child.try_wait().ok().flatten().is_none() {
                all_exited = false;
            }
        }
        if all_exited || Instant::now() >= deadline {
            break;
        }
        sleep(VM_CHILD_POLL_INTERVAL).await;
    }

    for child in children.iter_mut() {
        if child.child.try_wait().ok().flatten().is_none() {
            let _ = child.child.start_kill();
        }
    }
    for child in children.iter_mut() {
        let _ = child.child.wait().await;
    }
}

#[cfg(unix)]
fn send_sigterm(pid: u32) -> Result<()> {
    let pid = i32::try_from(pid).into_diagnostic()?;
    let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
    if rc == 0 {
        Ok(())
    } else {
        Err(miette::miette!(
            "failed to send SIGTERM to process {}: {}",
            pid,
            std::io::Error::last_os_error()
        ))
    }
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    let mut out = String::from("'");
    for ch in value.chars() {
        if ch == '\'' {
            out.push_str("'\"'\"'");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

async fn send_qemu_powerdown(socket_path: &Path) -> Result<()> {
    let stream = UnixStream::connect(socket_path)
        .await
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to connect to QMP socket {}", socket_path.display()))?;
    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();
    wait_for_qmp_greeting(&mut lines, socket_path).await?;
    write_half
        .write_all(b"{\"execute\":\"qmp_capabilities\"}\n")
        .await
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to negotiate QMP capabilities on {}",
                socket_path.display()
            )
        })?;
    wait_for_qmp_success(&mut lines, socket_path, "qmp_capabilities").await?;
    write_half
        .write_all(b"{\"execute\":\"system_powerdown\"}\n")
        .await
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to request QEMU powerdown on {}",
                socket_path.display()
            )
        })?;
    wait_for_qmp_success(&mut lines, socket_path, "system_powerdown").await
}

async fn wait_for_qmp_greeting(
    lines: &mut tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
    socket_path: &Path,
) -> Result<()> {
    loop {
        let line = timeout(VM_QMP_RESPONSE_TIMEOUT, lines.next_line())
            .await
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "timed out waiting for QMP greeting from {}",
                    socket_path.display()
                )
            })?
            .into_diagnostic()
            .wrap_err_with(|| {
                format!("failed to read QMP greeting from {}", socket_path.display())
            })?
            .ok_or_else(|| {
                miette::miette!(
                    "QMP socket {} closed before sending a greeting",
                    socket_path.display()
                )
            })?;
        let message: Value = serde_json::from_str(&line).map_err(|err| {
            miette::miette!("invalid QMP greeting from {}: {err}", socket_path.display())
        })?;
        if message.get("QMP").is_some() {
            return Ok(());
        }
    }
}

async fn wait_for_qmp_success(
    lines: &mut tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
    socket_path: &Path,
    command_name: &str,
) -> Result<()> {
    loop {
        let line = timeout(VM_QMP_RESPONSE_TIMEOUT, lines.next_line())
            .await
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "timed out waiting for QMP response to {} on {}",
                    command_name,
                    socket_path.display()
                )
            })?
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "failed to read QMP response to {} on {}",
                    command_name,
                    socket_path.display()
                )
            })?
            .ok_or_else(|| {
                miette::miette!(
                    "QMP socket {} closed while waiting for {}",
                    socket_path.display(),
                    command_name
                )
            })?;
        let message: Value = serde_json::from_str(&line).map_err(|err| {
            miette::miette!(
                "invalid QMP response to {} on {}: {err}",
                command_name,
                socket_path.display()
            )
        })?;
        if message.get("return").is_some() {
            return Ok(());
        }
        if let Some(error) = message.get("error") {
            return Err(miette::miette!(
                "QMP command {} failed on {}: {}",
                command_name,
                socket_path.display(),
                error
            ));
        }
    }
}

fn decode_b64_json(name: &'static str, raw: &str) -> Result<Value> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw.as_bytes())
        .map_err(|err| miette::miette!("invalid base64 in {name}: {err}"))?;
    serde_json::from_slice::<Value>(&bytes)
        .map_err(|err| miette::miette!("invalid json in {name}: {err}"))
}

fn decode_b64_json_t<T>(name: &'static str, raw: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw.as_bytes())
        .map_err(|err| miette::miette!("invalid base64 in {name}: {err}"))?;
    serde_json::from_slice::<T>(&bytes)
        .map_err(|err| miette::miette!("invalid json in {name}: {err}"))
}

#[cfg(test)]
mod tests;
