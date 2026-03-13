use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    env,
    fmt::Write as _,
    fs::{self, File},
    hash::{Hash as _, Hasher as _},
    io::{Seek as _, SeekFrom, Write as _},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
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
    build_root_config, env_var_for_path, eval_config_template_partial_with_context, get_by_path,
    get_by_path_opt, render_template_string_with_context, stringify_for_mount,
};
use amber_mesh::{
    InboundTarget, MESH_CONFIG_FILENAME, MESH_IDENTITY_FILENAME, MESH_PROVISION_PLAN_VERSION,
    MeshConfigPublic, MeshIdentity, MeshIdentityPublic, MeshIdentitySecret, MeshPeer,
    MeshProvisionOutput, MeshProvisionPlan, MeshProvisionTarget,
};
use amber_template::{
    ConfigTemplatePayload, RuntimeSlotObject, RuntimeTemplateContext, TemplatePart,
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

const VM_CHILD_POLL_INTERVAL: Duration = Duration::from_millis(150);
const VM_RUNTIME_STATE_POLL_INTERVAL: Duration = Duration::from_millis(50);
const VM_SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(15);
const VM_GUESTFWD_READY_TIMEOUT: Duration = Duration::from_secs(5);
const VM_QMP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);

const VM_RUNTIME_DISK_LABEL: [u8; 11] = *b"AMBERRUN   ";
const VM_RUNTIME_DISK_SIZE: u64 = 64 * 1024 * 1024;
const VM_HOST_GUESTFWD_IP: &str = "10.0.2.100";

const MANAGED_PROCESS_PATH: &str = "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/\
                                    local/sbin:/usr/bin:/bin:/usr/sbin:/sbin";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct VmRuntimeState {
    #[serde(default)]
    pub(crate) slot_ports_by_component: BTreeMap<usize, BTreeMap<String, u16>>,
    #[serde(default)]
    pub(crate) slot_route_ports_by_component: BTreeMap<usize, BTreeMap<String, Vec<u16>>>,
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

#[derive(Clone, Debug, PartialEq, Eq)]
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

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QemuAccel {
    Hvf,
    Kvm,
    Tcg,
}

#[derive(Debug, Deserialize)]
struct QemuImgInfo {
    format: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum MountSpec {
    Literal {
        path: String,
        content: String,
    },
    Config {
        path: String,
        config: String,
        optional: bool,
    },
}

pub(crate) async fn run_vm_init(plan: PathBuf, storage_root: Option<PathBuf>) -> Result<()> {
    let plan_path = canonicalize_path(&plan, "vm plan")?;
    let plan_root = plan_path
        .parent()
        .ok_or_else(|| miette::miette!("invalid vm plan path {}", plan_path.display()))?
        .to_path_buf();
    let storage_root = vm_storage_root(&plan_root, storage_root.as_deref())
        .into_diagnostic()
        .wrap_err("failed to resolve vm storage root")?;

    let vm_plan: VmPlan = read_json_file(&plan_path, "vm plan")?;
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

    let runtime_dir = tempfile::Builder::new()
        .prefix("amber-vm-")
        .tempdir()
        .into_diagnostic()
        .wrap_err("failed to create vm runtime workspace")?;
    let runtime_root = runtime_dir.path().to_path_buf();
    let runtime_state_path = vm_runtime_state_path(&plan_root);
    let mut children = Vec::<ManagedChild>::new();
    let mut log_tasks = Vec::new();
    let mut control_socket_paths = None;

    let supervision = async {
        provision_mesh_filesystem(&mesh_plan, &runtime_root)?;
        if runtime_state_path.exists() {
            let _ = fs::remove_file(&runtime_state_path);
        }

        let port_assignments = assign_vm_runtime_ports(&runtime_root, &vm_plan)?;
        write_vm_runtime_state(&plan_root, &port_assignments.state)?;

        let router_binary = resolve_host_binary("amber-router")?;
        if let Some(router) = vm_plan.router.as_ref() {
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
                component_config.as_ref(),
            )?;
            wait_for_guestfwd_targets(component, &port_assignments, VM_GUESTFWD_READY_TIMEOUT)?;
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
                component_config.as_ref(),
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

pub(crate) fn vm_storage_root(
    plan_root: &Path,
    override_root: Option<&Path>,
) -> std::io::Result<PathBuf> {
    if let Some(override_root) = override_root {
        return Ok(if override_root.is_absolute() {
            override_root.to_path_buf()
        } else {
            env::current_dir()?.join(override_root)
        });
    }

    let name = plan_root
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("amber-vm");
    let parent = plan_root.parent().unwrap_or_else(|| Path::new("."));
    Ok(parent.join(format!(".{name}.amber-state")))
}

pub(crate) fn vm_runtime_state_path(plan_root: &Path) -> PathBuf {
    plan_root.join(".amber").join("vm-runtime.json")
}

pub(crate) fn vm_current_control_socket_path(plan_root: &Path) -> PathBuf {
    hashed_temp_socket_path("amber-vm-control", "current", plan_root)
}

pub(crate) fn vm_runtime_control_socket_path(runtime_root: &Path) -> PathBuf {
    hashed_temp_socket_path("amber-vm-control", "runtime", runtime_root)
}

pub(crate) fn load_vm_runtime_state(plan_root: &Path) -> Result<Option<VmRuntimeState>> {
    let path = vm_runtime_state_path(plan_root);
    if !path.is_file() {
        return Ok(None);
    }
    read_json_file(&path, "vm runtime state").map(Some)
}

pub(crate) async fn wait_for_vm_runtime_router_port(
    plan_root: &Path,
    timeout: Duration,
) -> Result<u16> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(port) =
            load_vm_runtime_state(plan_root)?.and_then(|state| state.router_mesh_port)
        {
            return Ok(port);
        }

        let now = Instant::now();
        if now >= deadline {
            break;
        }
        sleep((deadline - now).min(VM_RUNTIME_STATE_POLL_INTERVAL)).await;
    }

    Err(miette::miette!(
        "vm runtime router mesh port is unavailable; start `amber run` first or pass --router-addr"
    ))
}

fn canonicalize_path(path: &Path, description: &str) -> Result<PathBuf> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir().into_diagnostic()?.join(path)
    };
    abs.canonicalize()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to resolve {description} path {}", abs.display()))
}

fn read_json_file<T>(path: &Path, description: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let raw = fs::read_to_string(path).map_err(|err| {
        miette::miette!("failed to read {} {}: {err}", description, path.display())
    })?;
    serde_json::from_str(&raw)
        .map_err(|err| miette::miette!("invalid {} {}: {err}", description, path.display()))
}

fn write_vm_runtime_state(plan_root: &Path, state: &VmRuntimeState) -> Result<()> {
    let path = vm_runtime_state_path(plan_root);
    let parent = path
        .parent()
        .ok_or_else(|| miette::miette!("invalid vm runtime state path"))?;
    fs::create_dir_all(parent)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create vm runtime state dir {}", parent.display()))?;
    let json = serde_json::to_string_pretty(state)
        .map_err(|err| miette::miette!("failed to serialize vm runtime state: {err}"))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create temporary vm runtime state file in {}",
                parent.display()
            )
        })?;
    temp.write_all(json.as_bytes())
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to write temporary vm runtime state {}",
                path.display()
            )
        })?;
    temp.flush().into_diagnostic().wrap_err_with(|| {
        format!(
            "failed to flush temporary vm runtime state {}",
            path.display()
        )
    })?;
    let _ = temp.persist(&path).map_err(|err| {
        miette::miette!("failed to write vm runtime state {}: {err}", path.display())
    })?;
    Ok(())
}

fn hashed_temp_socket_path(namespace: &str, kind: &str, path: &Path) -> PathBuf {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut hasher);
    let suffix = hasher.finish();
    env::temp_dir()
        .join(namespace)
        .join(format!("{kind}-{suffix:016x}.sock"))
}

fn assign_vm_runtime_ports(runtime_root: &Path, vm_plan: &VmPlan) -> Result<VmPortAssignments> {
    let mut state = VmRuntimeState::default();
    let mut reserved = BTreeSet::new();
    let mut mesh_port_by_peer_id = HashMap::<String, u16>::new();
    let mut component_configs = Vec::<(PathBuf, MeshConfigPublic)>::new();
    let mut route_host_ports_by_component = BTreeMap::<usize, BTreeMap<String, Vec<u16>>>::new();

    for component in &vm_plan.components {
        let path = runtime_root.join(&component.mesh_config_path);
        let mut config = read_mesh_config_public(&path)?;
        let mesh_port = allocate_runtime_port(&mut reserved)?;
        mesh_port_by_peer_id.insert(config.identity.id.clone(), mesh_port);
        config.mesh_listen = SocketAddr::new(config.mesh_listen.ip(), mesh_port);

        let mut route_guest_host_pairs = BTreeMap::<String, Vec<(u16, u16)>>::new();
        for route in &mut config.outbound {
            let guest_port = route.listen_port;
            let host_port = allocate_runtime_port(&mut reserved)?;
            route.listen_port = host_port;
            route_guest_host_pairs
                .entry(route.slot.clone())
                .or_default()
                .push((guest_port, host_port));
        }
        for ports in route_guest_host_pairs.values_mut() {
            ports.sort_unstable_by_key(|(guest_port, _)| *guest_port);
        }
        let slot_guest_ports = route_guest_host_pairs
            .iter()
            .map(|(slot, pairs)| {
                (
                    slot.clone(),
                    pairs
                        .iter()
                        .map(|(guest_port, _)| *guest_port)
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let slot_host_ports = route_guest_host_pairs
            .into_iter()
            .map(|(slot, pairs)| {
                (
                    slot,
                    pairs
                        .into_iter()
                        .map(|(_, host_port)| host_port)
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<BTreeMap<_, _>>();

        let mut endpoint_forwards = BTreeMap::new();
        for route in &mut config.inbound {
            if let InboundTarget::Local { port } = &mut route.target {
                let guest_port = *port;
                let host_port = if let Some(existing) = endpoint_forwards.get(&guest_port) {
                    *existing
                } else {
                    let host_port = allocate_runtime_port(&mut reserved)?;
                    endpoint_forwards.insert(guest_port, host_port);
                    host_port
                };
                *port = host_port;
            }
        }

        let slot_ports = slot_guest_ports
            .iter()
            .filter_map(|(slot, ports)| (ports.len() == 1).then_some((slot.clone(), ports[0])))
            .collect::<BTreeMap<_, _>>();

        state
            .component_mesh_port_by_id
            .insert(component.id, mesh_port);
        state
            .slot_ports_by_component
            .insert(component.id, slot_ports);
        state
            .slot_route_ports_by_component
            .insert(component.id, slot_guest_ports);
        state
            .endpoint_forwards_by_component
            .insert(component.id, endpoint_forwards);
        route_host_ports_by_component.insert(component.id, slot_host_ports);
        component_configs.push((path, config));
    }

    let mut router_config = if let Some(router) = vm_plan.router.as_ref() {
        let path = runtime_root.join(&router.mesh_config_path);
        let mut config = read_mesh_config_public(&path)?;
        let mesh_port = allocate_runtime_port(&mut reserved)?;
        mesh_port_by_peer_id.insert(config.identity.id.clone(), mesh_port);
        config.mesh_listen = SocketAddr::new(config.mesh_listen.ip(), mesh_port);
        state.router_mesh_port = Some(mesh_port);
        Some((path, config))
    } else {
        None
    };

    for (_, config) in &mut component_configs {
        rewrite_mesh_peer_addrs(config, &mesh_port_by_peer_id)?;
    }
    if let Some((_, config)) = router_config.as_mut() {
        rewrite_mesh_peer_addrs(config, &mesh_port_by_peer_id)?;
    }

    for (path, config) in component_configs {
        write_mesh_config_public(&path, &config)?;
    }
    if let Some((path, config)) = router_config {
        write_mesh_config_public(&path, &config)?;
    }

    Ok(VmPortAssignments {
        state,
        route_host_ports_by_component,
    })
}

fn allocate_runtime_port(reserved: &mut BTreeSet<u16>) -> Result<u16> {
    for _ in 0..256 {
        let port = pick_free_port()?;
        if reserved.insert(port) {
            return Ok(port);
        }
    }
    Err(miette::miette!(
        "ran out of ports while allocating vm runtime ports"
    ))
}

fn pick_free_port() -> Result<u16> {
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .into_diagnostic()?;
    Ok(listener.local_addr().into_diagnostic()?.port())
}

fn rewrite_mesh_peer_addrs(
    config: &mut MeshConfigPublic,
    mesh_port_by_peer_id: &HashMap<String, u16>,
) -> Result<()> {
    for route in &mut config.outbound {
        let port = mesh_port_by_peer_id
            .get(route.peer_id.as_str())
            .copied()
            .ok_or_else(|| miette::miette!("missing mesh port for peer {}", route.peer_id))?;
        let addr = route.peer_addr.parse::<SocketAddr>().map_err(|err| {
            miette::miette!("invalid mesh peer address {}: {err}", route.peer_addr)
        })?;
        route.peer_addr = SocketAddr::new(addr.ip(), port).to_string();
    }

    for route in &mut config.inbound {
        if let InboundTarget::MeshForward {
            peer_addr, peer_id, ..
        } = &mut route.target
        {
            let port = mesh_port_by_peer_id
                .get(peer_id.as_str())
                .copied()
                .ok_or_else(|| miette::miette!("missing mesh port for peer {}", peer_id))?;
            let addr = peer_addr
                .parse::<SocketAddr>()
                .map_err(|err| miette::miette!("invalid mesh peer address {}: {err}", peer_addr))?;
            *peer_addr = SocketAddr::new(addr.ip(), port).to_string();
        }
    }

    Ok(())
}

fn read_mesh_config_public(path: &Path) -> Result<MeshConfigPublic> {
    read_json_file(path, "mesh config")
}

fn write_mesh_config_public(path: &Path, config: &MeshConfigPublic) -> Result<()> {
    let json = serde_json::to_string_pretty(config).map_err(|err| {
        miette::miette!("failed to serialize mesh config {}: {err}", path.display())
    })?;
    fs::write(path, json)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write mesh config {}", path.display()))
}

fn provision_mesh_filesystem(plan: &MeshProvisionPlan, root: &Path) -> Result<()> {
    let mut identities = HashMap::<String, MeshIdentity>::new();
    for target in &plan.targets {
        let id = target.config.identity.id.clone();
        identities.entry(id).or_insert_with(|| {
            MeshIdentity::generate(
                target.config.identity.id.clone(),
                target.config.identity.mesh_scope.clone(),
            )
        });
    }

    for target in &plan.targets {
        let output_dir = output_dir_for_target(root, target)?;
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
        let public_config = render_public_mesh_config(&target.config, &identities)?;

        let identity_json = serde_json::to_string_pretty(&identity_secret)
            .map_err(|err| miette::miette!("failed to serialize mesh identity: {err}"))?;
        let config_json = serde_json::to_string_pretty(&public_config)
            .map_err(|err| miette::miette!("failed to serialize mesh config: {err}"))?;
        let identity_path = output_dir.join(MESH_IDENTITY_FILENAME);
        let config_path = output_dir.join(MESH_CONFIG_FILENAME);
        fs::write(&identity_path, identity_json)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!("failed to write mesh identity {}", identity_path.display())
            })?;
        fs::write(&config_path, config_json)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to write mesh config {}", config_path.display()))?;
    }

    Ok(())
}

fn render_public_mesh_config(
    template: &amber_mesh::MeshConfigTemplate,
    identities: &HashMap<String, MeshIdentity>,
) -> Result<MeshConfigPublic> {
    let peers = template
        .peers
        .iter()
        .map(|peer| {
            let identity = identities
                .get(&peer.id)
                .ok_or_else(|| miette::miette!("missing mesh peer identity {}", peer.id))?;
            Ok(MeshPeer {
                id: identity.id.clone(),
                public_key: identity.public_key,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let identity = identities
        .get(&template.identity.id)
        .ok_or_else(|| miette::miette!("missing mesh identity {}", template.identity.id))?;
    Ok(MeshConfigPublic {
        identity: MeshIdentityPublic::from_identity(identity),
        mesh_listen: template.mesh_listen,
        control_listen: template.control_listen,
        control_allow: template.control_allow.clone(),
        peers,
        inbound: template.inbound.clone(),
        outbound: template.outbound.clone(),
        transport: template.transport.clone(),
    })
}

fn output_dir_for_target(root: &Path, target: &MeshProvisionTarget) -> Result<PathBuf> {
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
            "vm runtime does not support kubernetes provision target {}",
            name
        )),
    }
}

async fn spawn_vm_router(
    router_binary: &str,
    runtime_root: &Path,
    plan_root: &Path,
    router: &VmRouterPlan,
    children: &mut Vec<ManagedChild>,
    log_tasks: &mut Vec<tokio::task::JoinHandle<()>>,
) -> Result<VmControlSocketPaths> {
    let paths = VmControlSocketPaths {
        artifact_link: resolve_artifact_path(plan_root, &router.control_socket_path),
        current_link: vm_current_control_socket_path(plan_root),
        runtime: vm_runtime_control_socket_path(runtime_root),
    };
    let artifact_dir = paths
        .artifact_link
        .parent()
        .ok_or_else(|| miette::miette!("invalid vm control socket path"))?;
    let current_dir = paths
        .current_link
        .parent()
        .ok_or_else(|| miette::miette!("invalid current vm control socket path"))?;
    let runtime_dir = paths
        .runtime
        .parent()
        .ok_or_else(|| miette::miette!("invalid runtime vm control socket path"))?;
    fs::create_dir_all(artifact_dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create vm control dir {}", artifact_dir.display()))?;
    fs::create_dir_all(current_dir)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create current vm control dir {}",
                current_dir.display()
            )
        })?;
    fs::create_dir_all(runtime_dir)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create runtime vm control dir {}",
                runtime_dir.display()
            )
        })?;
    if paths.runtime.exists() {
        fs::remove_file(&paths.runtime)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "failed to remove stale runtime vm control socket {}",
                    paths.runtime.display()
                )
            })?;
    }
    ensure_control_socket_link(
        &paths.artifact_link,
        &paths.current_link,
        "vm router control symlink",
    )?;
    ensure_control_socket_link(
        &paths.current_link,
        &paths.runtime,
        "runtime vm router control symlink",
    )?;

    let mut env_map = BTreeMap::new();
    env_map.insert(
        "AMBER_ROUTER_CONFIG_PATH".to_string(),
        runtime_root
            .join(&router.mesh_config_path)
            .display()
            .to_string(),
    );
    env_map.insert(
        "AMBER_ROUTER_IDENTITY_PATH".to_string(),
        runtime_root
            .join(&router.mesh_identity_path)
            .display()
            .to_string(),
    );
    env_map.insert(
        "AMBER_ROUTER_CONTROL_SOCKET_PATH".to_string(),
        paths.runtime.display().to_string(),
    );
    for passthrough in &router.env_passthrough {
        if let Ok(value) = env::var(passthrough) {
            env_map.insert(passthrough.clone(), value);
        }
    }
    let work_dir = runtime_root.join("work/router");
    fs::create_dir_all(&work_dir)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create router runtime directory {}",
                work_dir.display()
            )
        })?;

    spawn_command(
        "router".to_string(),
        vec![router_binary.to_string()],
        &work_dir,
        env_map,
        ManagedChildShutdown::Signal,
        children,
        log_tasks,
    )
    .await?;

    Ok(paths)
}

async fn spawn_component_sidecar(
    router_binary: &str,
    runtime_root: &Path,
    component: &VmComponentPlan,
    children: &mut Vec<ManagedChild>,
    log_tasks: &mut Vec<tokio::task::JoinHandle<()>>,
) -> Result<()> {
    let mut env_map = BTreeMap::new();
    env_map.insert(
        "AMBER_ROUTER_CONFIG_PATH".to_string(),
        runtime_root
            .join(&component.mesh_config_path)
            .display()
            .to_string(),
    );
    env_map.insert(
        "AMBER_ROUTER_IDENTITY_PATH".to_string(),
        runtime_root
            .join(&component.mesh_identity_path)
            .display()
            .to_string(),
    );
    let work_dir = runtime_root
        .join("work")
        .join("sidecars")
        .join(&component.log_name);
    fs::create_dir_all(&work_dir)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create sidecar runtime directory {}",
                work_dir.display()
            )
        })?;
    spawn_command(
        format!("{}-sidecar", component.log_name),
        vec![router_binary.to_string()],
        &work_dir,
        env_map,
        ManagedChildShutdown::Signal,
        children,
        log_tasks,
    )
    .await?;
    Ok(())
}

fn resolve_artifact_path(plan_root: &Path, path: &str) -> PathBuf {
    let path = Path::new(path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        plan_root.join(path)
    }
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

fn remove_control_socket_link(paths: &VmControlSocketPaths) {
    #[cfg(unix)]
    {
        if fs::read_link(&paths.current_link)
            .ok()
            .is_some_and(|target| target == paths.runtime)
        {
            let _ = fs::remove_file(&paths.current_link);
        }
    }

    #[cfg(not(unix))]
    {
        let _ = fs::remove_file(&paths.current_link);
    }
}

async fn cleanup_vm_runtime(
    children: &mut [ManagedChild],
    log_tasks: Vec<tokio::task::JoinHandle<()>>,
    runtime_state_path: &Path,
    control_socket_paths: Option<&VmControlSocketPaths>,
    runtime_dir: tempfile::TempDir,
) {
    terminate_children(children).await;
    for task in log_tasks {
        let _ = task.await;
    }
    if let Some(paths) = control_socket_paths {
        remove_control_socket_link(paths);
        let _ = fs::remove_file(&paths.runtime);
    }
    let _ = fs::remove_file(runtime_state_path);
    drop(runtime_dir);
}

fn render_mount_files(
    mount_spec_b64: Option<&str>,
    component_config: Option<&Value>,
) -> Result<Vec<RenderedMountFile>> {
    let Some(mount_spec_b64) = mount_spec_b64 else {
        return Ok(Vec::new());
    };
    let mounts = decode_b64_json_t::<Vec<MountSpec>>("AMBER_MOUNT_SPEC_B64", mount_spec_b64)?;
    if mounts.is_empty() {
        return Ok(Vec::new());
    }
    let mut rendered = Vec::with_capacity(mounts.len());
    for mount in mounts {
        let (path, contents) = match mount {
            MountSpec::Literal { path, content } => (path, content),
            MountSpec::Config {
                path,
                config,
                optional,
            } => {
                let component_config = component_config.ok_or_else(|| {
                    miette::miette!(
                        "mount {} requires config resolution but no runtime config payload was \
                         provided",
                        path
                    )
                })?;
                (
                    path,
                    if optional {
                        match get_by_path_opt(component_config, &config).map_err(|err| {
                            miette::miette!("failed to resolve config mount {}: {err}", config)
                        })? {
                            Some(value) => stringify_for_mount(value)
                                .map_err(|err| miette::miette!("{err}"))?,
                            None => String::new(),
                        }
                    } else {
                        let value = get_by_path(component_config, &config).map_err(|err| {
                            miette::miette!("failed to resolve config mount {}: {err}", config)
                        })?;
                        stringify_for_mount(value).map_err(|err| miette::miette!("{err}"))?
                    },
                )
            }
        };
        if !Path::new(&path).is_absolute() {
            return Err(miette::miette!(
                "vm mount path {} must be absolute",
                Path::new(&path).display()
            ));
        }
        rendered.push(RenderedMountFile {
            guest_path: path,
            contents,
        });
    }
    Ok(rendered)
}

fn build_component_config(
    payload: Option<&DirectRuntimeConfigPayload>,
    runtime_context: &RuntimeTemplateContext,
) -> Result<Option<Value>> {
    let Some(payload) = payload else {
        return Ok(None);
    };
    let root_schema = decode_b64_json("AMBER_ROOT_CONFIG_SCHEMA_B64", &payload.root_schema_b64)?;
    let component_schema = decode_b64_json(
        "AMBER_COMPONENT_CONFIG_SCHEMA_B64",
        &payload.component_schema_b64,
    )?;
    let component_template_value = decode_b64_json(
        "AMBER_COMPONENT_CONFIG_TEMPLATE_B64",
        &payload.component_cfg_template_b64,
    )?;
    let component_template = ConfigTemplatePayload::from_value(component_template_value)
        .map_err(|err| miette::miette!("invalid component config template: {err}"))?;

    let mut config_env = BTreeMap::new();
    for path in &payload.allowed_root_leaf_paths {
        let env_var = env_var_for_path(path)
            .map_err(|err| miette::miette!("failed to map config path {}: {err}", path))?;
        if let Ok(value) = env::var(&env_var) {
            config_env.insert(env_var, value);
        }
    }
    let root_config = build_root_config(&root_schema, &config_env)
        .map_err(|err| miette::miette!("failed to build root config: {err}"))?;
    let component_config = eval_config_template_partial_with_context(
        &component_template,
        &root_config,
        runtime_context,
    )
    .map_err(|err| miette::miette!("failed to render component config: {err}"))?;

    if !component_config.is_object() {
        return Err(miette::miette!(
            "resolved component config must be an object"
        ));
    }

    let validator = jsonschema::validator_for(&component_schema)
        .map_err(|err| miette::miette!("failed to compile component schema: {err}"))?;
    {
        let mut errors = validator.iter_errors(&component_config);
        if let Some(first) = errors.next() {
            let mut messages = vec![first.to_string()];
            messages.extend(errors.take(7).map(|err| err.to_string()));
            return Err(miette::miette!(
                "resolved component config does not satisfy its schema: {}",
                messages.join("; ")
            ));
        }
    }

    Ok(Some(component_config))
}

fn build_vm_runtime_template_context(
    runtime_addresses: &DirectRuntimeAddressPlan,
    runtime_state: &VmRuntimeState,
) -> Result<RuntimeTemplateContext> {
    let mut context = RuntimeTemplateContext::default();

    for (scope, entries) in &runtime_addresses.slots_by_scope {
        let mut urls = BTreeMap::new();
        for (name, source) in entries {
            let url = runtime_url_for_source(source, runtime_state)?;
            urls.insert(
                name.clone(),
                serde_json::to_string(&RuntimeSlotObject { url: url.clone() }).map_err(|err| {
                    miette::miette!(
                        "failed to serialize vm runtime slot object for scope {} slot {}: {err}",
                        scope,
                        name
                    )
                })?,
            );
            urls.insert(format!("{name}.url"), url);
        }
        if !urls.is_empty() {
            context.slots_by_scope.insert(*scope as u64, urls);
        }
    }

    for (scope, entries) in &runtime_addresses.slot_items_by_scope {
        let mut urls = BTreeMap::new();
        for (name, sources) in entries {
            let mut items = Vec::with_capacity(sources.len());
            for source in sources {
                items.push(RuntimeSlotObject {
                    url: runtime_url_for_source(source, runtime_state)?,
                });
            }
            urls.insert(name.clone(), items);
        }
        if !urls.is_empty() {
            context.slot_items_by_scope.insert(*scope as u64, urls);
        }
    }

    Ok(context)
}

fn runtime_url_for_source(
    source: &DirectRuntimeUrlSource,
    runtime_state: &VmRuntimeState,
) -> Result<String> {
    match source {
        DirectRuntimeUrlSource::Slot {
            component_id,
            slot,
            scheme,
        } => {
            let port = runtime_state
                .slot_ports_by_component
                .get(component_id)
                .and_then(|slots| slots.get(slot.as_str()))
                .copied()
                .ok_or_else(|| {
                    miette::miette!(
                        "missing vm runtime slot port for component {} slot {}",
                        component_id,
                        slot
                    )
                })?;
            Ok(format!("{scheme}://{VM_RUNTIME_SLOT_HOST}:{port}"))
        }
        DirectRuntimeUrlSource::SlotItem {
            component_id,
            slot,
            item_index,
            scheme,
        } => {
            let port = runtime_state
                .slot_route_ports_by_component
                .get(component_id)
                .and_then(|slots| slots.get(slot.as_str()))
                .and_then(|ports| ports.get(*item_index))
                .copied()
                .ok_or_else(|| {
                    miette::miette!(
                        "missing vm runtime slot item {} for component {} slot {}",
                        item_index,
                        component_id,
                        slot
                    )
                })?;
            Ok(format!("{scheme}://{VM_RUNTIME_SLOT_HOST}:{port}"))
        }
    }
}

fn wait_for_guestfwd_targets(
    component: &VmComponentPlan,
    port_assignments: &VmPortAssignments,
    timeout: Duration,
) -> Result<()> {
    let Some(slot_ports) = port_assignments
        .route_host_ports_by_component
        .get(&component.id)
    else {
        return Ok(());
    };
    for ports in slot_ports.values() {
        for port in ports {
            wait_for_local_listener(*port, timeout).map_err(|err| {
                miette::miette!(
                    "guestfwd target 127.0.0.1:{} for component {} did not become ready: {err}",
                    port,
                    component.moniker
                )
            })?;
        }
    }
    Ok(())
}

fn wait_for_local_listener(port: u16, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    while Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(miette::miette!("timeout after {:?}", timeout))
}

fn build_vm_launch_plan(
    host: VmHostContext<'_>,
    component: &VmComponentPlan,
    port_assignments: &VmPortAssignments,
    runtime_context: &RuntimeTemplateContext,
    component_config: Option<&Value>,
    mount_files: &[RenderedMountFile],
) -> Result<VmLaunchPlan> {
    let vm_root = host.runtime_root.join("vms").join(&component.log_name);
    fs::create_dir_all(&vm_root)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to create vm runtime directory {}",
                vm_root.display()
            )
        })?;

    let base_image = resolve_vm_base_image(&component.base_image)?;
    let overlay_path = vm_root.join("root-overlay.qcow2");
    create_overlay_image(host.qemu_img, &base_image, &overlay_path)?;

    let runtime_disk_path = if mount_files.is_empty() {
        None
    } else {
        let runtime_disk_path = vm_root.join("runtime.img");
        let runtime_disk_files = build_runtime_disk_files(mount_files)?;
        write_fat_image(
            &runtime_disk_path,
            VM_RUNTIME_DISK_SIZE,
            VM_RUNTIME_DISK_LABEL,
            &runtime_disk_files,
        )?;
        Some(runtime_disk_path)
    };

    let seed_disk_path = vm_root.join("seed.iso");
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
        &seed_disk_path,
        &user_data,
        &meta_data,
        vendor_data.as_deref(),
    )?;

    let mut persistent_paths = Vec::new();
    for mount in &component.storage_mounts {
        let disk_path = storage_image_path(host.storage_root, mount);
        ensure_persistent_image(host.qemu_img, &disk_path, &mount.size)?;
        persistent_paths.push((mount, disk_path));
    }

    let cpus = resolve_vm_scalar(&component.cpus, "program.vm.cpus")?;
    let memory_mib = resolve_vm_scalar(&component.memory_mib, "program.vm.memory_mib")?;
    let netdev_arg = build_qemu_user_netdev_arg(host.amber_cli, component, port_assignments)?;
    let qmp_socket = vm_root.join("qmp.sock");
    let serial_log = vm_root.join("serial.log");
    let mut command = vec![
        host.qemu_system.display().to_string(),
        "-name".to_string(),
        format!("amber-{}", component.log_name),
        "-display".to_string(),
        "none".to_string(),
        "-monitor".to_string(),
        "none".to_string(),
        "-serial".to_string(),
        format!("file:{}", serial_log.display()),
        "-qmp".to_string(),
        format!("unix:{},server=on,wait=off", qmp_socket.display()),
        "-no-reboot".to_string(),
        "-smp".to_string(),
        cpus.to_string(),
        "-m".to_string(),
        memory_mib.to_string(),
    ];
    command.extend(qemu_machine_args(host.arch, host.accel)?);
    command.extend([
        "-device".to_string(),
        "virtio-rng-pci".to_string(),
        "-netdev".to_string(),
        netdev_arg,
        "-device".to_string(),
        "virtio-net-pci,netdev=net0".to_string(),
    ]);
    push_qemu_block_device(
        &mut command,
        "root",
        "qcow2",
        &overlay_path,
        false,
        None,
        Some(1),
    );
    push_qemu_block_device(
        &mut command,
        "seed",
        "raw",
        &seed_disk_path,
        true,
        None,
        None,
    );
    if let Some(runtime_disk_path) = runtime_disk_path.as_ref() {
        push_qemu_block_device(
            &mut command,
            "runtime",
            "raw",
            runtime_disk_path,
            true,
            Some("amber-runtime"),
            None,
        );
    }
    for (mount, disk_path) in persistent_paths {
        push_qemu_block_device(
            &mut command,
            &mount.serial,
            "qcow2",
            &disk_path,
            false,
            Some(mount.serial.as_str()),
            None,
        );
    }

    Ok(VmLaunchPlan {
        name: component.log_name.clone(),
        command,
        qmp_socket,
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
    let mut device = format!("virtio-blk-pci,drive={id}");
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

fn resolve_vm_scalar(plan: &VmScalarPlanU32, field_name: &str) -> Result<u32> {
    let value = match plan {
        VmScalarPlanU32::Literal { value } => *value,
        VmScalarPlanU32::RuntimeConfig { query } => {
            let env_var = env_var_for_path(query).map_err(|err| {
                miette::miette!("failed to map {field_name} query {}: {err}", query)
            })?;
            let raw = env::var(&env_var).map_err(|_| {
                miette::miette!(
                    "{field_name} references config path {}, but {} is not set",
                    query,
                    env_var
                )
            })?;
            raw.trim().parse::<u32>().map_err(|err| {
                miette::miette!(
                    "{field_name} expected an unsigned integer from {}={}, got {} ({err})",
                    env_var,
                    raw,
                    raw
                )
            })?
        }
    };
    if value == 0 {
        return Err(miette::miette!("{field_name} must be greater than zero"));
    }
    Ok(value)
}

fn resolve_vm_base_image(plan: &VmHostPathPlan) -> Result<PathBuf> {
    let raw_path = match plan {
        VmHostPathPlan::Static { path } => path.clone(),
        VmHostPathPlan::RuntimeConfig { query, source_dir } => {
            let path = resolve_vm_runtime_config(query, "program.vm.image")?;
            return resolve_vm_runtime_host_path(&path, source_dir.as_deref());
        }
        VmHostPathPlan::RuntimeTemplate { parts, source_dir } => {
            let rendered = render_vm_host_path_template(parts)?;
            return resolve_vm_runtime_host_path(&rendered, source_dir.as_deref());
        }
    };
    resolve_vm_runtime_host_path(&raw_path, None)
}

fn render_vm_host_path_template(parts: &[VmHostPathPart]) -> Result<String> {
    let mut rendered = String::new();
    for part in parts {
        match part {
            VmHostPathPart::Literal { value } => rendered.push_str(value),
            VmHostPathPart::RuntimeConfig { query } => {
                rendered.push_str(&resolve_vm_runtime_config(query, "program.vm.image")?);
            }
        }
    }
    Ok(rendered)
}

fn resolve_vm_runtime_config(query: &str, field_name: &str) -> Result<String> {
    let env_var = env_var_for_path(query)
        .map_err(|err| miette::miette!("failed to map {field_name} query {}: {err}", query))?;
    env::var(&env_var).map_err(|_| {
        miette::miette!(
            "{field_name} references config path {}, but {} is not set",
            query,
            env_var
        )
    })
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

fn create_overlay_image(qemu_img: &Path, base_image: &Path, overlay_path: &Path) -> Result<()> {
    let base_info = qemu_img_info(qemu_img, base_image)?;
    if overlay_path.exists() {
        fs::remove_file(overlay_path)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!("failed to remove stale overlay {}", overlay_path.display())
            })?;
    }
    run_checked_command(
        ProcessCommand::new(qemu_img)
            .arg("create")
            .arg("-f")
            .arg("qcow2")
            .arg("-F")
            .arg(&base_info.format)
            .arg("-b")
            .arg(base_image)
            .arg(overlay_path),
        "create vm overlay image",
    )
}

fn ensure_persistent_image(qemu_img: &Path, path: &Path, size: &str) -> Result<()> {
    if path.is_file() {
        return Ok(());
    }
    let size = normalize_qemu_image_size(size)?;
    let parent = path
        .parent()
        .ok_or_else(|| miette::miette!("invalid persistent storage path {}", path.display()))?;
    fs::create_dir_all(parent)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create storage directory {}", parent.display()))?;
    run_checked_command(
        ProcessCommand::new(qemu_img)
            .arg("create")
            .arg("-f")
            .arg("qcow2")
            .arg(path)
            .arg(&size),
        "create vm persistent storage image",
    )
}

fn normalize_qemu_image_size(size: &str) -> Result<String> {
    let trimmed = size.trim();
    if trimmed.is_empty() {
        return Err(miette::miette!("vm storage size must not be empty"));
    }
    for (suffix, qemu_suffix) in [
        ("KiB", "K"),
        ("Ki", "K"),
        ("MiB", "M"),
        ("Mi", "M"),
        ("GiB", "G"),
        ("Gi", "G"),
        ("TiB", "T"),
        ("Ti", "T"),
        ("PiB", "P"),
        ("Pi", "P"),
        ("EiB", "E"),
        ("Ei", "E"),
    ] {
        if let Some(number) = trimmed.strip_suffix(suffix) {
            let number = number.trim();
            if number.is_empty() {
                return Err(miette::miette!("vm storage size must not be empty"));
            }
            return Ok(format!("{number}{qemu_suffix}"));
        }
    }
    Ok(trimmed.to_string())
}

fn storage_image_path(
    storage_root: &Path,
    mount: &amber_compiler::reporter::vm::VmStorageMount,
) -> PathBuf {
    storage_root
        .join(&mount.state_subdir)
        .with_extension("qcow2")
}

fn qemu_img_info(qemu_img: &Path, image: &Path) -> Result<QemuImgInfo> {
    let output = ProcessCommand::new(qemu_img)
        .arg("info")
        .arg("--output=json")
        .arg(image)
        .output()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to inspect vm image {}", image.display()))?;
    if !output.status.success() {
        return Err(miette::miette!(
            "failed to inspect vm image {}: {}",
            image.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|err| {
        miette::miette!(
            "invalid qemu-img info output for {}: {err}",
            image.display()
        )
    })
}

fn run_checked_command(command: &mut ProcessCommand, description: &str) -> Result<()> {
    let rendered = render_process_command(command);
    let output = command
        .output()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to {description}: {rendered}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(miette::miette!(
        "failed to {description}: {}\nstdout:\n{}\nstderr:\n{}",
        rendered,
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn render_process_command(command: &ProcessCommand) -> String {
    let program = command.get_program().to_string_lossy();
    let args = command
        .get_args()
        .map(|arg| shell_quote(&arg.to_string_lossy()))
        .collect::<Vec<_>>()
        .join(" ");
    if args.is_empty() {
        program.into_owned()
    } else {
        format!("{program} {args}")
    }
}

fn write_fat_image(
    path: &Path,
    size: u64,
    volume_label: [u8; 11],
    files: &[RuntimeDiskFile],
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to create image directory {}", parent.display()))?;
    }
    let file = File::options()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create image {}", path.display()))?;
    file.set_len(size)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to size image {}", path.display()))?;
    let mut file = file;
    format_volume(
        &mut file,
        FormatVolumeOptions::new().volume_label(volume_label),
    )
    .into_diagnostic()
    .wrap_err_with(|| format!("failed to format FAT image {}", path.display()))?;
    file.seek(SeekFrom::Start(0))
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to rewind FAT image {}", path.display()))?;
    let fs = FileSystem::new(file, FsOptions::new())
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to open FAT image {}", path.display()))?;
    let root = fs.root_dir();
    for item in files {
        let path = Path::new(&item.path);
        if path.is_absolute() {
            return Err(miette::miette!(
                "FAT image path {} must be relative",
                path.display()
            ));
        }
        let mut parent = root.clone();
        let components = path
            .components()
            .map(|component| component.as_os_str().to_string_lossy().to_string())
            .collect::<Vec<_>>();
        for component in components.iter().take(components.len().saturating_sub(1)) {
            parent = match parent.open_dir(component) {
                Ok(dir) => dir,
                Err(_) => parent
                    .create_dir(component)
                    .into_diagnostic()
                    .wrap_err_with(|| {
                        format!(
                            "failed to create FAT directory {} in {}",
                            component,
                            path.display()
                        )
                    })?,
            };
        }
        let file_name = components
            .last()
            .ok_or_else(|| miette::miette!("FAT image entry path must not be empty"))?;
        let mut file = parent
            .create_file(file_name)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "failed to create FAT image file {} in {}",
                    file_name,
                    path.display()
                )
            })?;
        file.write_all(&item.contents)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to write FAT image file {}", path.display()))?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum CloudInitSeedTool {
    #[cfg(target_os = "macos")]
    Hdiutil,
    #[cfg(target_os = "linux")]
    Genisoimage,
    #[cfg(target_os = "linux")]
    Mkisofs,
    #[cfg(target_os = "linux")]
    Xorriso,
    #[cfg(target_os = "linux")]
    CloudLocalds,
}

fn write_cloud_init_seed_image(
    path: &Path,
    user_data: &str,
    meta_data: &str,
    vendor_data: Option<&str>,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!("failed to create seed image directory {}", parent.display())
            })?;
    }
    if path.exists() {
        fs::remove_file(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to remove stale seed image {}", path.display()))?;
    }

    let staging = tempfile::Builder::new()
        .prefix("amber-vm-seed-")
        .tempdir()
        .into_diagnostic()
        .wrap_err("failed to create cloud-init seed staging directory")?;
    fs::write(staging.path().join("user-data"), user_data)
        .into_diagnostic()
        .wrap_err("failed to write cloud-init user-data")?;
    fs::write(staging.path().join("meta-data"), meta_data)
        .into_diagnostic()
        .wrap_err("failed to write cloud-init meta-data")?;
    if let Some(vendor_data) = vendor_data {
        fs::write(staging.path().join("vendor-data"), vendor_data)
            .into_diagnostic()
            .wrap_err("failed to write cloud-init vendor-data")?;
    }

    match detect_cloud_init_seed_tool(vendor_data.is_some())? {
        #[cfg(target_os = "macos")]
        CloudInitSeedTool::Hdiutil => run_checked_command(
            ProcessCommand::new("/usr/bin/hdiutil")
                .arg("makehybrid")
                .arg("-quiet")
                .arg("-iso")
                .arg("-joliet")
                .arg("-default-volume-name")
                .arg("CIDATA")
                .arg("-o")
                .arg(path)
                .arg(staging.path()),
            "create vm cloud-init seed image",
        ),
        #[cfg(target_os = "linux")]
        CloudInitSeedTool::Genisoimage => run_checked_command(
            ProcessCommand::new("genisoimage")
                .current_dir(staging.path())
                .arg("-quiet")
                .arg("-volid")
                .arg("CIDATA")
                .arg("-joliet")
                .arg("-rock")
                .arg("-output")
                .arg(path)
                .arg("user-data")
                .arg("meta-data")
                .args(vendor_data.map(|_| "vendor-data")),
            "create vm cloud-init seed image",
        ),
        #[cfg(target_os = "linux")]
        CloudInitSeedTool::Mkisofs => run_checked_command(
            ProcessCommand::new("mkisofs")
                .current_dir(staging.path())
                .arg("-quiet")
                .arg("-volid")
                .arg("CIDATA")
                .arg("-joliet")
                .arg("-rock")
                .arg("-output")
                .arg(path)
                .arg("user-data")
                .arg("meta-data")
                .args(vendor_data.map(|_| "vendor-data")),
            "create vm cloud-init seed image",
        ),
        #[cfg(target_os = "linux")]
        CloudInitSeedTool::Xorriso => run_checked_command(
            ProcessCommand::new("xorriso")
                .current_dir(staging.path())
                .arg("-as")
                .arg("mkisofs")
                .arg("-quiet")
                .arg("-volid")
                .arg("CIDATA")
                .arg("-joliet")
                .arg("-rock")
                .arg("-output")
                .arg(path)
                .arg("user-data")
                .arg("meta-data")
                .args(vendor_data.map(|_| "vendor-data")),
            "create vm cloud-init seed image",
        ),
        #[cfg(target_os = "linux")]
        CloudInitSeedTool::CloudLocalds => run_checked_command(
            ProcessCommand::new("cloud-localds")
                .arg("--filesystem")
                .arg("iso")
                .arg(path)
                .arg(staging.path().join("user-data"))
                .arg(staging.path().join("meta-data")),
            "create vm cloud-init seed image",
        ),
    }
}

#[cfg(target_os = "macos")]
fn detect_cloud_init_seed_tool(needs_vendor_data: bool) -> Result<CloudInitSeedTool> {
    let _ = needs_vendor_data;
    Ok(CloudInitSeedTool::Hdiutil)
}

#[cfg(target_os = "linux")]
fn detect_cloud_init_seed_tool(needs_vendor_data: bool) -> Result<CloudInitSeedTool> {
    if find_executable_in_path("genisoimage").is_some() {
        return Ok(CloudInitSeedTool::Genisoimage);
    }
    if find_executable_in_path("mkisofs").is_some() {
        return Ok(CloudInitSeedTool::Mkisofs);
    }
    if find_executable_in_path("xorriso").is_some() {
        return Ok(CloudInitSeedTool::Xorriso);
    }
    if !needs_vendor_data && find_executable_in_path("cloud-localds").is_some() {
        return Ok(CloudInitSeedTool::CloudLocalds);
    }
    if needs_vendor_data {
        return Err(miette::miette!(
            "building a VM cloud-init seed with vendor-data requires one of `genisoimage`, \
             `mkisofs`, or `xorriso` on PATH"
        ));
    }
    Err(miette::miette!(
        "building a VM cloud-init seed requires one of `genisoimage`, `mkisofs`, `xorriso`, or \
         `cloud-localds` on PATH"
    ))
}

#[cfg(target_os = "linux")]
fn find_executable_in_path(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

fn build_runtime_disk_files(mount_files: &[RenderedMountFile]) -> Result<Vec<RuntimeDiskFile>> {
    let mut files = Vec::new();
    files.push(RuntimeDiskFile {
        path: "apply-mounts.sh".to_string(),
        contents: render_mount_apply_script(mount_files).into_bytes(),
    });
    for (index, mount) in mount_files.iter().enumerate() {
        files.push(RuntimeDiskFile {
            path: format!("mounts/file-{index:04}"),
            contents: mount.contents.as_bytes().to_vec(),
        });
    }
    Ok(files)
}

fn render_mount_apply_script(mount_files: &[RenderedMountFile]) -> String {
    let mut script = String::from("#!/bin/sh\nset -eu\n");
    for (index, mount) in mount_files.iter().enumerate() {
        let source = format!("/amber/runtime/mounts/file-{index:04}");
        let target = mount.guest_path.as_str();
        let parent = Path::new(target)
            .parent()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "/".to_string());
        let _ = writeln!(script, "mkdir -p {}", shell_quote(&parent));
        let _ = writeln!(
            script,
            "cp {} {}",
            shell_quote(&source),
            shell_quote(target)
        );
    }
    script
}

fn render_user_data(
    component: &VmComponentPlan,
    component_config: Option<&Value>,
    runtime_context: &RuntimeTemplateContext,
) -> Result<String> {
    let generated = format!("#cloud-boothook\n{}", render_bootstrap_script(component));
    let extra = render_vm_template_string(
        component.cloud_init_user_data.as_ref(),
        component_config,
        runtime_context,
    )?;
    Ok(match extra.as_deref() {
        None => generated,
        Some(extra) => render_cloud_init_multipart(&generated, extra),
    })
}

fn render_vm_template_string(
    plan: Option<&VmTemplateStringPlan>,
    component_config: Option<&Value>,
    runtime_context: &RuntimeTemplateContext,
) -> Result<Option<String>> {
    let Some(plan) = plan else {
        return Ok(None);
    };
    match plan {
        VmTemplateStringPlan::Static { value } => Ok(Some(value.clone())),
        VmTemplateStringPlan::RuntimeTemplate { parts } => {
            let requires_config = parts
                .iter()
                .any(|part| matches!(part, TemplatePart::Config { .. }));
            let empty = Value::Object(Default::default());
            let component_config = match (requires_config, component_config) {
                (true, None) => {
                    return Err(miette::miette!(
                        "vm template requires runtime config, but no runtime config payload was \
                         provided"
                    ));
                }
                (true, Some(config)) => config,
                (false, Some(config)) => config,
                (false, None) => &empty,
            };
            render_template_string_with_context(parts, component_config, runtime_context)
                .map(Some)
                .map_err(|err| miette::miette!("failed to render vm template: {err}"))
        }
    }
}

fn render_bootstrap_script(component: &VmComponentPlan) -> String {
    let mut script = String::from("#!/bin/sh\nexec >/dev/console 2>&1\nset -eux\n");
    let mut next_data_disk_index = 2usize;
    if component.mount_spec_b64.is_some() {
        script.push_str("mkdir -p /amber/runtime\n");
        script.push_str("for _ in $(seq 1 60); do [ -b /dev/vdc ] && break; sleep 1; done\n");
        script.push_str("[ -b /dev/vdc ] || { echo missing runtime helper disk >&2; exit 1; }\n");
        script.push_str("mount -t vfat -o ro,exec /dev/vdc /amber/runtime\n");
        script.push_str(
            "if [ -f /amber/runtime/apply-mounts.sh ]; then /bin/sh \
             /amber/runtime/apply-mounts.sh; fi\n",
        );
        next_data_disk_index += 1;
    }
    for (index, mount) in component.storage_mounts.iter().enumerate() {
        let dev = format!(
            "/dev/vd{}",
            (b'a' + (next_data_disk_index + index) as u8) as char
        );
        let mount_path = shell_quote(&mount.mount_path);
        let dev_quoted = shell_quote(&dev);
        let _ = writeln!(script, "mkdir -p {mount_path}");
        let _ = writeln!(
            script,
            "for _ in $(seq 1 60); do [ -b {dev_quoted} ] && break; sleep 1; done"
        );
        let _ = writeln!(
            script,
            "[ -b {dev_quoted} ] || {{ echo missing storage device {dev_quoted} >&2; exit 1; }}"
        );
        let _ = writeln!(
            script,
            "if ! blkid {dev_quoted} >/dev/null 2>&1; then mkfs.ext4 -F {dev_quoted}; fi"
        );
        let _ = writeln!(
            script,
            "mount {dev_quoted} {mount_path} || mount -o rw {dev_quoted} {mount_path}"
        );
    }
    script.push_str("sync || true\n");
    script.push_str("exit 0\n");
    script
}

fn render_cloud_init_multipart(generated: &str, extra: &str) -> String {
    const BOUNDARY: &str = "===============amber-vm-boundary==";
    let generated_type = cloud_init_content_type(generated);
    let extra_type = cloud_init_content_type(extra);
    format!(
        "MIME-Version: 1.0\nContent-Type: multipart/mixed; \
         boundary=\"{BOUNDARY}\"\n\n--{BOUNDARY}\nContent-Type: {generated_type}; \
         charset=\"us-ascii\"\n\n{generated}\n--{BOUNDARY}\nContent-Type: {extra_type}; \
         charset=\"us-ascii\"\n\n{extra}\n--{BOUNDARY}--\n"
    )
}

fn cloud_init_content_type(raw: &str) -> &'static str {
    let trimmed = raw.trim_start();
    if trimmed.starts_with("#cloud-config") {
        "text/cloud-config"
    } else if trimmed.starts_with("#cloud-boothook") {
        "text/cloud-boothook"
    } else if trimmed.starts_with("#!") {
        "text/x-shellscript"
    } else {
        "text/plain"
    }
}

fn build_qemu_user_netdev_arg(
    amber_cli: &str,
    component: &VmComponentPlan,
    port_assignments: &VmPortAssignments,
) -> Result<String> {
    let mut netdev = format!(
        "user,id=net0,hostname={},restrict={}",
        component.log_name,
        match component.egress {
            VmEgressPlan::None => "on",
            VmEgressPlan::Optional => "off",
        }
    );
    if let Some(slot_ports) = port_assignments
        .state
        .slot_route_ports_by_component
        .get(&component.id)
    {
        let slot_host_ports = port_assignments
            .route_host_ports_by_component
            .get(&component.id)
            .ok_or_else(|| {
                miette::miette!(
                    "missing host slot ports for component {}",
                    component.moniker
                )
            })?;
        for (slot, guest_ports) in slot_ports {
            let host_ports = slot_host_ports.get(slot.as_str()).ok_or_else(|| {
                miette::miette!(
                    "missing guestfwd host ports for component {} slot {}",
                    component.moniker,
                    slot
                )
            })?;
            if guest_ports.len() != host_ports.len() {
                return Err(miette::miette!(
                    "slot {} for component {} has mismatched guest/host port counts",
                    slot,
                    component.moniker
                ));
            }
            for (guest_port, host_port) in guest_ports.iter().zip(host_ports) {
                let bridge_command = guestfwd_bridge_command(amber_cli, *host_port);
                let _ = write!(
                    netdev,
                    ",guestfwd=tcp:{VM_HOST_GUESTFWD_IP}:{guest_port}-cmd:{bridge_command}"
                );
            }
        }
    }
    if let Some(endpoint_ports) = port_assignments
        .state
        .endpoint_forwards_by_component
        .get(&component.id)
    {
        for (guest_port, host_port) in endpoint_ports {
            let _ = write!(netdev, ",hostfwd=tcp:127.0.0.1:{host_port}-:{guest_port}");
        }
    }
    Ok(netdev)
}

fn guestfwd_bridge_command(amber_cli: &str, host_port: u16) -> String {
    format!(
        "{} run-vm-guestfwd-bridge {}",
        shell_quote_posix(amber_cli),
        shell_quote_posix(&SocketAddr::from(([127, 0, 0, 1], host_port)).to_string())
    )
}

fn shell_quote_posix(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    if value
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'/' | b'.' | b'_' | b'-' | b':' | b'@' | b'%'))
    {
        return value.to_string();
    }

    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn qemu_machine_args(arch: VmArch, accel: QemuAccel) -> Result<Vec<String>> {
    let mut args = match arch {
        VmArch::Aarch64 => vec![
            "-machine".to_string(),
            "virt,highmem=off".to_string(),
            "-cpu".to_string(),
            match accel {
                QemuAccel::Hvf | QemuAccel::Kvm => "host".to_string(),
                QemuAccel::Tcg => "max".to_string(),
            },
        ],
        VmArch::X86_64 => vec![
            "-machine".to_string(),
            "q35".to_string(),
            "-cpu".to_string(),
            match accel {
                QemuAccel::Hvf | QemuAccel::Kvm => "host".to_string(),
                QemuAccel::Tcg => "max".to_string(),
            },
        ],
    };
    args.extend(match accel {
        QemuAccel::Hvf => vec!["-accel".to_string(), "hvf".to_string()],
        QemuAccel::Kvm => vec!["-accel".to_string(), "kvm".to_string()],
        QemuAccel::Tcg => vec!["-accel".to_string(), "tcg".to_string()],
    });
    if arch == VmArch::Aarch64 {
        let firmware = resolve_aarch64_firmware()?;
        args.extend(["-bios".to_string(), firmware.display().to_string()]);
    }
    Ok(args)
}

fn resolve_qemu_system_binary() -> Result<PathBuf> {
    if let Ok(value) = env::var("AMBER_VM_QEMU_SYSTEM") {
        let path = PathBuf::from(value);
        if path.is_file() {
            return Ok(path);
        }
        return Err(miette::miette!(
            "AMBER_VM_QEMU_SYSTEM points to a missing file: {}",
            path.display()
        ));
    }
    let name = match host_arch()? {
        VmArch::Aarch64 => "qemu-system-aarch64",
        VmArch::X86_64 => "qemu-system-x86_64",
    };
    find_in_path(name).ok_or_else(|| {
        miette::miette!(
            "could not locate runtime binary `{name}`; set AMBER_VM_QEMU_SYSTEM or add it to PATH"
        )
    })
}

fn resolve_qemu_img_binary() -> Result<PathBuf> {
    if let Ok(value) = env::var("AMBER_VM_QEMU_IMG") {
        let path = PathBuf::from(value);
        if path.is_file() {
            return Ok(path);
        }
        return Err(miette::miette!(
            "AMBER_VM_QEMU_IMG points to a missing file: {}",
            path.display()
        ));
    }
    find_in_path("qemu-img").ok_or_else(|| {
        miette::miette!(
            "could not locate runtime binary `qemu-img`; set AMBER_VM_QEMU_IMG or add it to PATH"
        )
    })
}

fn resolve_host_binary(name: &str) -> Result<String> {
    if let Ok(dir) = env::var("AMBER_RUNTIME_BIN_DIR") {
        let candidate = Path::new(&dir).join(name);
        if candidate.is_file() {
            return Ok(candidate.display().to_string());
        }
        return Err(miette::miette!(
            "runtime binary `{name}` was not found in AMBER_RUNTIME_BIN_DIR ({})",
            Path::new(&dir).display()
        ));
    }

    if let Ok(current_exe) = env::current_exe()
        && let Some(bin_dir) = current_exe.parent()
    {
        for dir in [Some(bin_dir), bin_dir.parent()].into_iter().flatten() {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Ok(candidate.display().to_string());
            }
        }
    }

    if let Some(candidate) = find_in_path(name) {
        return Ok(candidate.display().to_string());
    }

    Err(miette::miette!(
        "could not locate runtime binary `{name}`; set AMBER_RUNTIME_BIN_DIR, place it next to \
         the `amber` binary, or add it to PATH"
    ))
}

fn resolve_aarch64_firmware() -> Result<PathBuf> {
    if let Ok(path) = env::var("AMBER_VM_AARCH64_FIRMWARE") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
        return Err(miette::miette!(
            "AMBER_VM_AARCH64_FIRMWARE points to a missing file: {}",
            path.display()
        ));
    }

    let candidates = [
        "/opt/homebrew/share/qemu/edk2-aarch64-code.fd",
        "/usr/local/share/qemu/edk2-aarch64-code.fd",
        "/usr/share/AAVMF/AAVMF_CODE.fd",
        "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd",
        "/usr/share/edk2/aarch64/QEMU_EFI.fd",
        "/usr/share/edk2/ovmf/AAVMF_CODE.fd",
    ];
    candidates
        .iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            miette::miette!("could not locate AArch64 UEFI firmware; set AMBER_VM_AARCH64_FIRMWARE")
        })
}

fn host_arch() -> Result<VmArch> {
    match env::consts::ARCH {
        "aarch64" => Ok(VmArch::Aarch64),
        "x86_64" => Ok(VmArch::X86_64),
        other => Err(miette::miette!(
            "vm runtime supports only aarch64 and x86_64 hosts, found {}",
            other
        )),
    }
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
mod tests {
    use amber_compiler::reporter::vm::{MESH_PROVISION_PLAN_FILENAME, VmStorageMount};
    use amber_mesh::{MeshProtocol, OutboundRoute, TransportConfig};

    use super::*;

    #[test]
    fn vm_storage_root_defaults_next_to_output() {
        let root = vm_storage_root(Path::new("/tmp/out"), None).expect("storage root");
        assert_eq!(root, Path::new("/tmp/.out.amber-state"));
    }

    #[test]
    fn vm_runtime_control_socket_path_is_unique_per_run() {
        let first = tempfile::tempdir().expect("temp dir");
        let second = tempfile::tempdir().expect("temp dir");
        assert_ne!(
            vm_runtime_control_socket_path(first.path()),
            vm_runtime_control_socket_path(second.path())
        );
    }

    #[test]
    fn build_vm_runtime_template_context_uses_guest_slot_host() {
        let runtime_addresses = DirectRuntimeAddressPlan {
            slots_by_scope: BTreeMap::from([(
                3,
                BTreeMap::from([(
                    "api".to_string(),
                    DirectRuntimeUrlSource::Slot {
                        component_id: 7,
                        slot: "api".to_string(),
                        scheme: "http".to_string(),
                    },
                )]),
            )]),
            slot_items_by_scope: BTreeMap::from([(
                5,
                BTreeMap::from([(
                    "upstream".to_string(),
                    vec![
                        DirectRuntimeUrlSource::SlotItem {
                            component_id: 8,
                            slot: "upstream".to_string(),
                            item_index: 0,
                            scheme: "http".to_string(),
                        },
                        DirectRuntimeUrlSource::SlotItem {
                            component_id: 8,
                            slot: "upstream".to_string(),
                            item_index: 1,
                            scheme: "http".to_string(),
                        },
                    ],
                )]),
            )]),
        };
        let runtime_state = VmRuntimeState {
            slot_ports_by_component: BTreeMap::from([(
                7,
                BTreeMap::from([("api".to_string(), 31001)]),
            )]),
            slot_route_ports_by_component: BTreeMap::from([(
                8,
                BTreeMap::from([("upstream".to_string(), vec![32001, 32002])]),
            )]),
            endpoint_forwards_by_component: BTreeMap::new(),
            component_mesh_port_by_id: BTreeMap::new(),
            router_mesh_port: None,
        };

        let context =
            build_vm_runtime_template_context(&runtime_addresses, &runtime_state).expect("context");

        assert_eq!(
            context
                .slots_by_scope
                .get(&3)
                .and_then(|values| values.get("api")),
            Some(&r#"{"url":"http://10.0.2.100:31001"}"#.to_string())
        );
        assert_eq!(
            context
                .slot_items_by_scope
                .get(&5)
                .and_then(|values| values.get("upstream"))
                .map(|items| items
                    .iter()
                    .map(|item| item.url.as_str())
                    .collect::<Vec<_>>()),
            Some(vec!["http://10.0.2.100:32001", "http://10.0.2.100:32002"])
        );
    }

    #[test]
    fn assign_vm_runtime_ports_preserves_guest_slot_order() {
        let temp = tempfile::tempdir().expect("temp dir");
        let mesh_config_rel = PathBuf::from("mesh/components/app/mesh-config.json");
        let mesh_config_path = temp.path().join(&mesh_config_rel);
        fs::create_dir_all(mesh_config_path.parent().expect("parent")).expect("mkdir");

        let config = MeshConfigPublic {
            identity: MeshIdentityPublic {
                id: "/app".to_string(),
                public_key: [7; 32],
                mesh_scope: None,
            },
            mesh_listen: "127.0.0.1:19000".parse().expect("mesh"),
            control_listen: None,
            control_allow: None,
            peers: Vec::new(),
            inbound: Vec::new(),
            outbound: vec![
                OutboundRoute {
                    route_id: "route-b".to_string(),
                    slot: "upstream".to_string(),
                    capability_kind: Some("http".to_string()),
                    capability_profile: None,
                    listen_port: 20001,
                    listen_addr: None,
                    protocol: MeshProtocol::Http,
                    http_plugins: Vec::new(),
                    peer_addr: "127.0.0.1:18081".to_string(),
                    peer_id: "/app".to_string(),
                    capability: "api".to_string(),
                },
                OutboundRoute {
                    route_id: "route-a".to_string(),
                    slot: "upstream".to_string(),
                    capability_kind: Some("http".to_string()),
                    capability_profile: None,
                    listen_port: 20000,
                    listen_addr: None,
                    protocol: MeshProtocol::Http,
                    http_plugins: Vec::new(),
                    peer_addr: "127.0.0.1:18080".to_string(),
                    peer_id: "/app".to_string(),
                    capability: "api".to_string(),
                },
            ],
            transport: TransportConfig::NoiseIk {},
        };
        write_mesh_config_public(&mesh_config_path, &config).expect("write");

        let vm_plan = VmPlan {
            version: VM_PLAN_VERSION.to_string(),
            mesh_provision_plan: MESH_PROVISION_PLAN_FILENAME.to_string(),
            startup_order: vec![7],
            runtime_addresses: DirectRuntimeAddressPlan {
                slots_by_scope: BTreeMap::new(),
                slot_items_by_scope: BTreeMap::from([(
                    7,
                    BTreeMap::from([(
                        "upstream".to_string(),
                        vec![
                            DirectRuntimeUrlSource::SlotItem {
                                component_id: 7,
                                slot: "upstream".to_string(),
                                item_index: 0,
                                scheme: "http".to_string(),
                            },
                            DirectRuntimeUrlSource::SlotItem {
                                component_id: 7,
                                slot: "upstream".to_string(),
                                item_index: 1,
                                scheme: "http".to_string(),
                            },
                        ],
                    )]),
                )]),
            },
            components: vec![VmComponentPlan {
                id: 7,
                moniker: "/app".to_string(),
                log_name: "app".to_string(),
                depends_on: Vec::new(),
                mesh_config_path: mesh_config_rel.display().to_string(),
                mesh_identity_path: "mesh/components/app/mesh-identity.json".to_string(),
                cpus: VmScalarPlanU32::Literal { value: 1 },
                memory_mib: VmScalarPlanU32::Literal { value: 512 },
                base_image: VmHostPathPlan::Static {
                    path: "/tmp/base.img".to_string(),
                },
                cloud_init_user_data: None,
                cloud_init_vendor_data: None,
                egress: VmEgressPlan::None,
                storage_mounts: vec![VmStorageMount {
                    mount_path: "/data".to_string(),
                    state_subdir: "app/data-1234".to_string(),
                    serial: "amber-1234".to_string(),
                    size: "1G".to_string(),
                }],
                runtime_config: None,
                mount_spec_b64: None,
            }],
            router: None,
        };

        let assignments = assign_vm_runtime_ports(temp.path(), &vm_plan).expect("ports");
        let runtime_ports = assignments
            .state
            .slot_route_ports_by_component
            .get(&7)
            .and_then(|slots| slots.get("upstream"))
            .expect("runtime ports");
        assert_eq!(runtime_ports, &vec![20000, 20001]);
    }

    #[test]
    fn build_qemu_user_netdev_arg_uses_guestfwd_bridge_command() {
        let component = VmComponentPlan {
            id: 7,
            moniker: "/bound".to_string(),
            log_name: "bound".to_string(),
            depends_on: Vec::new(),
            mesh_config_path: "mesh/components/bound/mesh-config.json".to_string(),
            mesh_identity_path: "mesh/components/bound/mesh-identity.json".to_string(),
            cpus: VmScalarPlanU32::Literal { value: 1 },
            memory_mib: VmScalarPlanU32::Literal { value: 512 },
            base_image: VmHostPathPlan::Static {
                path: "/tmp/base.img".to_string(),
            },
            cloud_init_user_data: None,
            cloud_init_vendor_data: None,
            egress: VmEgressPlan::None,
            storage_mounts: Vec::new(),
            runtime_config: None,
            mount_spec_b64: None,
        };
        let assignments = VmPortAssignments {
            state: VmRuntimeState {
                slot_ports_by_component: BTreeMap::new(),
                slot_route_ports_by_component: BTreeMap::from([(
                    7,
                    BTreeMap::from([("api".to_string(), vec![20_000])]),
                )]),
                endpoint_forwards_by_component: BTreeMap::from([(
                    7,
                    BTreeMap::from([(8080, 33_655)]),
                )]),
                component_mesh_port_by_id: BTreeMap::new(),
                router_mesh_port: None,
            },
            route_host_ports_by_component: BTreeMap::from([(
                7,
                BTreeMap::from([("api".to_string(), vec![43_071])]),
            )]),
        };

        let netdev =
            build_qemu_user_netdev_arg("/tmp/amber cli", &component, &assignments).expect("netdev");

        assert!(netdev.contains("guestfwd=tcp:10.0.2.100:20000-cmd:'"));
        assert!(netdev.contains("/tmp/amber cli"));
        assert!(netdev.contains("run-vm-guestfwd-bridge 127.0.0.1:43071"));
        assert!(netdev.contains("hostfwd=tcp:127.0.0.1:33655-:8080"));
    }

    #[test]
    fn render_cloud_init_multipart_keeps_generated_and_user_parts() {
        let rendered = render_cloud_init_multipart(
            "#cloud-boothook\n#!/bin/sh\necho generated\n",
            "#!/bin/sh\necho hi\n",
        );
        assert!(rendered.contains("multipart/mixed"));
        assert!(rendered.contains("text/cloud-boothook"));
        assert!(rendered.contains("text/x-shellscript"));
    }

    #[test]
    fn render_mount_files_uses_empty_contents_for_missing_optional_config() {
        use base64::engine::general_purpose::STANDARD;

        let mounts = vec![MountSpec::Config {
            path: "/etc/secret.txt".to_string(),
            config: "secret_value".to_string(),
            optional: true,
        }];
        let mount_spec_b64 = STANDARD.encode(serde_json::to_vec(&mounts).unwrap());

        let rendered = render_mount_files(Some(&mount_spec_b64), Some(&serde_json::json!({})))
            .expect("render mount files");

        assert_eq!(
            rendered,
            vec![RenderedMountFile {
                guest_path: "/etc/secret.txt".to_string(),
                contents: String::new(),
            }]
        );
    }

    #[test]
    fn bootstrap_script_skips_runtime_helper_disk_when_component_has_no_file_mounts() {
        let component = VmComponentPlan {
            id: 1,
            moniker: "/app".to_string(),
            log_name: "app".to_string(),
            depends_on: Vec::new(),
            mesh_config_path: "mesh/components/app/mesh-config.json".to_string(),
            mesh_identity_path: "mesh/components/app/mesh-identity.json".to_string(),
            cpus: VmScalarPlanU32::Literal { value: 1 },
            memory_mib: VmScalarPlanU32::Literal { value: 512 },
            base_image: VmHostPathPlan::Static {
                path: "/tmp/base.img".to_string(),
            },
            cloud_init_user_data: None,
            cloud_init_vendor_data: None,
            egress: VmEgressPlan::None,
            storage_mounts: vec![VmStorageMount {
                mount_path: "/data".to_string(),
                state_subdir: "app/data-1234".to_string(),
                serial: "amber-1234".to_string(),
                size: "1G".to_string(),
            }],
            runtime_config: None,
            mount_spec_b64: None,
        };

        let script = render_bootstrap_script(&component);
        assert!(!script.contains("/amber/runtime"));
        assert!(script.contains("/dev/vdc"));
    }

    #[test]
    fn bootstrap_script_uses_runtime_disk_before_storage_when_file_mounts_exist() {
        let component = VmComponentPlan {
            id: 1,
            moniker: "/app".to_string(),
            log_name: "app".to_string(),
            depends_on: Vec::new(),
            mesh_config_path: "mesh/components/app/mesh-config.json".to_string(),
            mesh_identity_path: "mesh/components/app/mesh-identity.json".to_string(),
            cpus: VmScalarPlanU32::Literal { value: 1 },
            memory_mib: VmScalarPlanU32::Literal { value: 512 },
            base_image: VmHostPathPlan::Static {
                path: "/tmp/base.img".to_string(),
            },
            cloud_init_user_data: None,
            cloud_init_vendor_data: None,
            egress: VmEgressPlan::None,
            storage_mounts: vec![VmStorageMount {
                mount_path: "/data".to_string(),
                state_subdir: "app/data-1234".to_string(),
                serial: "amber-1234".to_string(),
                size: "1G".to_string(),
            }],
            runtime_config: None,
            mount_spec_b64: Some("ignored".to_string()),
        };

        let script = render_bootstrap_script(&component);
        assert!(script.contains("mount -t vfat -o ro,exec /dev/vdc /amber/runtime"));
        assert!(script.contains("/dev/vdd"));
    }

    #[test]
    fn resolve_vm_base_image_uses_source_dir_for_runtime_config_paths() {
        let temp = tempfile::tempdir().expect("temp dir");
        let image_dir = temp.path().join("images");
        fs::create_dir_all(&image_dir).expect("image dir");
        let image_path = image_dir.join("base.qcow2");
        fs::write(&image_path, []).expect("image file");

        unsafe {
            env::set_var("AMBER_CONFIG_CONFIG__VM_IMAGE", "images/base.qcow2");
        }

        let resolved = resolve_vm_base_image(&VmHostPathPlan::RuntimeConfig {
            query: "config.vm_image".to_string(),
            source_dir: Some(temp.path().display().to_string()),
        })
        .expect("base image");

        assert_eq!(resolved, image_path);

        unsafe {
            env::remove_var("AMBER_CONFIG_CONFIG__VM_IMAGE");
        }
    }
}
