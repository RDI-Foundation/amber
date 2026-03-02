use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    path::PathBuf,
};

use amber_config as rc;
use amber_manifest::{FrameworkCapabilityName, MountSource};
use amber_mesh::{MESH_CONFIG_FILENAME, MESH_IDENTITY_FILENAME, MeshProvisionOutput};
use amber_scenario::{ComponentId, Scenario};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::{
    CompileOutput,
    reporter::{Reporter, ReporterError},
    targets::mesh::{
        addressing::{
            DockerFrameworkBindingPolicy, LocalAddressing, LocalAddressingOptions,
            build_address_plan,
        },
        config::{
            ComponentExecutionPlan, ProgramImagePart, ProgramImagePlan,
            build_component_runtime_plan, build_config_plan,
        },
        internal_images::resolve_internal_images,
        mesh_config::{
            FRAMEWORK_DOCKER_URL_ENV, INTERNAL_FRAMEWORK_DOCKER_SLOT, MeshServiceName, ROUTER_ID,
            RouterPorts, ServiceMeshAddressing, build_mesh_config_plan, scenario_ir_digest,
        },
        plan::{
            MeshOptions, MeshPlan, ResolvedFrameworkBinding, component_label,
            map_program_components,
        },
        ports::{allocate_mesh_ports, allocate_slot_ports},
        provision::build_mesh_provision_plan,
        proxy_metadata::{ProxyMetadata, RouterMetadata, build_proxy_metadata},
    },
};

const MESH_NETWORK_NAME: &str = "amber_mesh";

const ROUTER_SERVICE_NAME: &str = "amber-router";
const DOCKER_GATEWAY_SERVICE_NAME: &str = "amber-docker-gateway";
const PROVISIONER_SERVICE_NAME: &str = "amber-provisioner";
const HELPER_VOLUME_NAME: &str = "amber-helper-bin";
const HELPER_INIT_SERVICE: &str = "amber-init";
const HELPER_BIN_DIR: &str = "/amber/bin";
const HELPER_BIN_PATH: &str = "/amber/bin/amber-helper";
const DOCKER_MOUNT_PROXY_SPEC_ENV: &str = "AMBER_DOCKER_MOUNT_PROXY_SPEC_B64";
const DOCKER_GATEWAY_CONFIG_ENV: &str = "AMBER_DOCKER_GATEWAY_CONFIG_JSON";
const DOCKER_GATEWAY_HOST_SOCK_ENV: &str = "AMBER_DOCKER_SOCK";
const DOCKER_GATEWAY_CONTAINER_SOCK: &str = "/var/run/docker.sock";
const DOCKER_GATEWAY_PORT: u16 = 23750;
const MESH_CONFIG_DIR: &str = "/amber/mesh";
const PROVISIONER_CONFIG_ROOT: &str = "/amber/provision";
const PROVISIONER_PLAN_CONFIG_NAME: &str = "amber-mesh-provision-plan";
const PROVISIONER_PLAN_PATH: &str = "/amber/plan/mesh-provision-plan.json";
const HOST_GATEWAY_ENTRY: &str = "host.docker.internal:host-gateway";
const ROUTER_CONTROL_SOCKET_PATH_IN_CONTAINER: &str = "/amber/control/router-control.sock";
const ROUTER_CONTROL_SOCKET_DIR_IN_CONTAINER: &str = "/amber/control";
const ROUTER_CONTROL_SOCKET_FILENAME: &str = "router-control.sock";
const ROUTER_CONTROL_SOCKET_HOST_ROOT: &str = "/tmp/amber-control";
const ROUTER_CONTROL_SOCKET_DIR_ENV: &str = "AMBER_ROUTER_CONTROL_SOCKET_DIR";
const COMPOSE_PROJECT_NAME_ENV: &str = "COMPOSE_PROJECT_NAME";

const COMPONENT_MESH_PORT_BASE: u16 = 23000;
const ROUTER_MESH_PORT_BASE: u16 = 24000;
const ROUTER_CONTROL_PORT_BASE: u16 = 24100;
const LOCAL_SLOT_PORT_BASE: u16 = 20000;

#[derive(Clone, Copy, Debug, Default)]
pub struct DockerComposeReporter;

impl Reporter for DockerComposeReporter {
    type Artifact = String;

    fn emit(&self, output: &CompileOutput) -> Result<Self::Artifact, ReporterError> {
        render_docker_compose(output)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct DockerComposeFile {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    volumes: BTreeMap<String, EmptyMap>,
    services: BTreeMap<String, Service>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    configs: BTreeMap<String, ComposeConfig>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    networks: BTreeMap<String, Network>,
    #[serde(rename = "x-amber", default, skip_serializing_if = "Option::is_none")]
    x_amber: Option<ProxyMetadata>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct EmptyMap {}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct Network {
    driver: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct ComposeConfig {
    content: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct ServiceConfigMount {
    source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct Service {
    image: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    cap_add: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    cap_drop: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    security_opt: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    networks: BTreeMap<String, EmptyMap>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    entrypoint: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    environment: Option<Environment>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    env_file: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    ports: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    extra_hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    volumes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    configs: Vec<ServiceConfigMount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    depends_on: Option<DependsOn>,
    #[serde(skip_serializing_if = "Option::is_none")]
    restart: Option<String>,
}

impl Service {
    fn new(image: impl Into<String>) -> Self {
        Self {
            image: image.into(),
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum Environment {
    List(Vec<String>),
    Map(BTreeMap<String, String>),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum DependsOn {
    List(Vec<String>),
    Conditions(BTreeMap<String, DependsOnCondition>),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct DependsOnCondition {
    condition: String,
}

#[derive(Clone, Debug)]
struct ServiceNames {
    program: String,
    sidecar: String,
}

impl MeshServiceName for ServiceNames {
    fn mesh_service_name(&self) -> &str {
        &self.sidecar
    }
}

#[derive(Clone, Debug, Serialize)]
struct DockerGatewayCallerConfig {
    host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    component: String,
    compose_service: String,
}

#[derive(Clone, Debug, Serialize)]
struct DockerGatewayConfig {
    listen: String,
    docker_sock: String,
    compose_project: String,
    callers: Vec<DockerGatewayCallerConfig>,
}

#[derive(Clone, Debug, Serialize)]
struct DockerMountProxySpec {
    path: String,
    tcp_host: String,
    tcp_port: u16,
}

#[derive(Debug)]
enum DockerComposeError {
    Other(String),
}

impl From<String> for DockerComposeError {
    fn from(value: String) -> Self {
        Self::Other(value)
    }
}

impl From<crate::targets::mesh::plan::MeshError> for DockerComposeError {
    fn from(value: crate::targets::mesh::plan::MeshError) -> Self {
        Self::Other(value.to_string())
    }
}

fn dc_other(err: impl ToString) -> DockerComposeError {
    DockerComposeError::Other(err.to_string())
}

impl DockerComposeError {
    fn into_reporter_error(self, _output: &CompileOutput) -> ReporterError {
        match self {
            DockerComposeError::Other(message) => ReporterError::new(message),
        }
    }
}

type DcResult<T> = Result<T, DockerComposeError>;

fn render_docker_compose(output: &CompileOutput) -> Result<String, ReporterError> {
    render_docker_compose_inner(output).map_err(|err| err.into_reporter_error(output))
}

fn render_docker_compose_inner(output: &CompileOutput) -> DcResult<String> {
    let s = &output.scenario;

    let mut mesh_plan = crate::targets::mesh::plan::build_mesh_plan(
        s,
        &output.store,
        MeshOptions {
            backend_label: "docker-compose reporter",
        },
    )
    .map_err(dc_other)?;
    let images = resolve_internal_images().map_err(DockerComposeError::Other)?;
    let docker_mount_paths_by_component =
        collect_framework_docker_mount_paths(s, mesh_plan.program_components.as_slice());
    add_mount_only_framework_docker_bindings(&mut mesh_plan, &docker_mount_paths_by_component);
    let program_components = mesh_plan.program_components.as_slice();

    // Precompute service names (injective & stable).
    let names: HashMap<ComponentId, ServiceNames> =
        map_program_components(s, program_components, |id, local_name| {
            let base = service_base_name(id, local_name);
            ServiceNames {
                program: base.clone(),
                sidecar: format!("{base}-net"),
            }
        });
    let docker_binding_components: BTreeSet<ComponentId> = mesh_plan
        .framework_bindings
        .iter()
        .filter(|binding| binding.capability.as_str() == "docker")
        .map(|binding| binding.consumer)
        .collect();
    let docker_mount_components: BTreeSet<ComponentId> =
        docker_mount_paths_by_component.keys().copied().collect();
    let docker_access_components: BTreeSet<ComponentId> = docker_binding_components
        .union(&docker_mount_components)
        .copied()
        .collect();
    let needs_docker_gateway = !docker_access_components.is_empty();
    let root_manifest = mesh_plan.manifests[s.root.0]
        .as_ref()
        .expect("root manifest should exist");
    let needs_router = !mesh_plan.external_bindings.is_empty()
        || !mesh_plan.exports.is_empty()
        || !mesh_plan.framework_bindings.is_empty();

    let mut slot_ports_by_component = allocate_slot_ports(s, program_components)?;
    ensure_internal_framework_slot_ports(s, &mut slot_ports_by_component, &mesh_plan)?;
    let mesh_ports_by_component = allocate_mesh_ports(
        s,
        program_components,
        COMPONENT_MESH_PORT_BASE,
        &slot_ports_by_component,
    )?;
    let docker_proxy_ports_by_component =
        docker_proxy_ports_by_component(s, &slot_ports_by_component, &mesh_plan)?;
    let router_ports = needs_router.then_some(RouterPorts {
        mesh: ROUTER_MESH_PORT_BASE,
        control: ROUTER_CONTROL_PORT_BASE,
    });

    let addressing = LocalAddressing::new(
        s,
        &slot_ports_by_component,
        LocalAddressingOptions {
            backend_label: "docker-compose reporter",
            docker_binding: DockerFrameworkBindingPolicy::LoopbackTcp,
        },
    );
    let address_plan = build_address_plan(&mesh_plan, addressing).map_err(dc_other)?;

    let router_mesh_port = router_ports
        .as_ref()
        .map(|ports| ports.mesh)
        .unwrap_or(ROUTER_MESH_PORT_BASE);
    let mesh_addressing = ServiceMeshAddressing::new(
        &names,
        None,
        &mesh_ports_by_component,
        ROUTER_SERVICE_NAME,
        router_mesh_port,
    );
    let mesh_config_plan = build_mesh_config_plan(
        s,
        &mesh_plan,
        root_manifest,
        &slot_ports_by_component,
        &mesh_ports_by_component,
        router_ports,
        &mesh_addressing,
    )
    .map_err(|err| DockerComposeError::Other(err.to_string()))?;
    let router_metadata = if needs_router {
        let control_socket = compose_control_socket_host_path_expr(s)?;
        Some(RouterMetadata {
            mesh_port: router_mesh_port,
            control_port: router_ports.as_ref().expect("router ports missing").control,
            control_socket: Some(control_socket),
        })
    } else {
        None
    };
    let proxy_metadata = needs_router.then_some(build_proxy_metadata(
        s,
        &mesh_plan,
        root_manifest,
        router_metadata,
    ));
    let exports_by_name = proxy_metadata
        .as_ref()
        .map(|meta| meta.exports.clone())
        .unwrap_or_default();
    let mesh_provision_plan = build_mesh_provision_plan(
        &mesh_config_plan,
        program_components,
        &names,
        |svc: &ServiceNames| MeshProvisionOutput::Filesystem {
            dir: provisioner_mount_dir(&svc.sidecar),
        },
        || MeshProvisionOutput::Filesystem {
            dir: provisioner_mount_dir(ROUTER_SERVICE_NAME),
        },
        |router_config| {
            router_config.control_listen = None;
            router_config.control_allow = None;
        },
    )
    .map_err(dc_other)?;
    let mut provisioner_mounts = Vec::new();
    for id in program_components {
        let svc = names.get(id).expect("service name missing");
        let volume = mesh_volume_name(&svc.sidecar);
        let mount_dir = provisioner_mount_dir(&svc.sidecar);
        provisioner_mounts.push((volume, mount_dir));
    }
    if needs_router {
        let volume = mesh_volume_name(ROUTER_SERVICE_NAME);
        let mount_dir = provisioner_mount_dir(ROUTER_SERVICE_NAME);
        provisioner_mounts.push((volume, mount_dir));
    }
    let needs_provisioner = !provisioner_mounts.is_empty();

    // Compose YAML
    // ---- runtime config / helper decision ----
    let config_plan = build_config_plan(
        s,
        program_components,
        &address_plan.slot_values_by_component,
        &address_plan.binding_values_by_component,
    )
    .map_err(dc_other)?;

    let root_leaves = &config_plan.root_leaves;
    let root_leaf_by_path: BTreeMap<&str, &rc::SchemaLeaf> = root_leaves
        .iter()
        .map(|leaf| (leaf.path.as_str(), leaf))
        .collect();
    let program_plans = &config_plan.program_plans;
    let any_helper = config_plan.needs_helper || !docker_mount_components.is_empty();

    let mut compose = DockerComposeFile::default();

    if any_helper {
        compose
            .volumes
            .insert(HELPER_VOLUME_NAME.to_string(), EmptyMap::default());

        let mut helper_init = Service::new(images.helper.clone());
        helper_init.entrypoint = Some(vec![
            "/amber-helper".to_string(),
            "install".to_string(),
            format!("{HELPER_BIN_DIR}/amber-helper"),
        ]);
        helper_init
            .volumes
            .push(format!("{HELPER_VOLUME_NAME}:{HELPER_BIN_DIR}"));
        helper_init.restart = Some("no".to_string());
        compose
            .services
            .insert(HELPER_INIT_SERVICE.to_string(), helper_init);
    }

    if needs_docker_gateway {
        let gateway_deps = docker_gateway_depends_on(needs_router);
        let gateway_service = docker_gateway_service(
            &images.docker_gateway,
            build_docker_gateway_config_json()?,
            gateway_deps,
        );
        compose
            .services
            .insert(DOCKER_GATEWAY_SERVICE_NAME.to_string(), gateway_service);
    }

    if needs_provisioner {
        let plan_json = serde_json::to_string(&mesh_provision_plan).map_err(|err| {
            DockerComposeError::Other(format!("failed to serialize mesh provision plan: {err}"))
        })?;

        let mut provisioner_service = Service::new(images.provisioner.clone());
        provisioner_service.user = Some("0:0".to_string());
        provisioner_service.cap_drop.push("ALL".to_string());
        provisioner_service
            .security_opt
            .push("no-new-privileges:true".to_string());
        provisioner_service.environment = Some(Environment::List(vec![format!(
            "AMBER_MESH_PROVISION_PLAN_PATH={PROVISIONER_PLAN_PATH}"
        )]));
        provisioner_service.configs.push(ServiceConfigMount {
            source: PROVISIONER_PLAN_CONFIG_NAME.to_string(),
            target: Some(PROVISIONER_PLAN_PATH.to_string()),
        });
        compose.configs.insert(
            PROVISIONER_PLAN_CONFIG_NAME.to_string(),
            ComposeConfig { content: plan_json },
        );
        for (volume, mount_dir) in &provisioner_mounts {
            compose
                .volumes
                .entry(volume.clone())
                .or_insert_with(EmptyMap::default);
            provisioner_service
                .volumes
                .push(format!("{volume}:{mount_dir}"));
        }
        provisioner_service.restart = Some("no".to_string());
        compose
            .services
            .insert(PROVISIONER_SERVICE_NAME.to_string(), provisioner_service);
    }

    if needs_router {
        let mut env_entries = mesh_config_plan.router_env_passthrough.clone();
        if needs_docker_gateway {
            env_entries.push(format!(
                "{FRAMEWORK_DOCKER_URL_ENV}=tcp://{DOCKER_GATEWAY_SERVICE_NAME}:\
                 {DOCKER_GATEWAY_PORT}"
            ));
        }
        env_entries.push(format!("AMBER_ROUTER_CONFIG_PATH={}", mesh_config_path()));
        env_entries.push(format!(
            "AMBER_ROUTER_IDENTITY_PATH={}",
            mesh_identity_path()
        ));
        env_entries.push(format!(
            "AMBER_ROUTER_CONTROL_SOCKET_PATH={ROUTER_CONTROL_SOCKET_PATH_IN_CONTAINER}"
        ));
        let mut router_service = Service::new(images.router.clone());
        router_service.environment = Some(Environment::List(env_entries));
        router_service
            .extra_hosts
            .push(HOST_GATEWAY_ENTRY.to_string());
        router_service
            .networks
            .insert(MESH_NETWORK_NAME.to_string(), EmptyMap::default());
        router_service
            .ports
            .push(format!("127.0.0.1:{router_mesh_port}:{router_mesh_port}"));

        if !exports_by_name.is_empty() {
            let labels_json = serde_json::to_string(&exports_by_name)
                .map_err(|err| format!("failed to serialize router export labels: {err}"))?;
            router_service
                .labels
                .insert("amber.exports".to_string(), labels_json);
        }

        let router_volume = mesh_volume_name(ROUTER_SERVICE_NAME);
        compose
            .volumes
            .entry(router_volume.clone())
            .or_insert_with(EmptyMap::default);
        router_service
            .volumes
            .push(format!("{router_volume}:{MESH_CONFIG_DIR}:ro"));
        router_service.volumes.push(format!(
            "{}:{}",
            compose_control_socket_host_dir_expr(s)?,
            ROUTER_CONTROL_SOCKET_DIR_IN_CONTAINER
        ));
        router_service.depends_on = build_depends_on(
            false,
            vec![(
                PROVISIONER_SERVICE_NAME.to_string(),
                "service_completed_successfully",
            )],
        );

        compose
            .services
            .insert(ROUTER_SERVICE_NAME.to_string(), router_service);
    }

    // Emit services in stable (component id) order, sidecar then program.
    for id in program_components {
        let svc = names.get(id).unwrap();

        let mut sidecar_service = Service::new(images.router.clone());
        sidecar_service.environment = Some(Environment::List(vec![
            format!("AMBER_ROUTER_CONFIG_PATH={}", mesh_config_path()),
            format!("AMBER_ROUTER_IDENTITY_PATH={}", mesh_identity_path()),
        ]));
        sidecar_service
            .networks
            .insert(MESH_NETWORK_NAME.to_string(), EmptyMap::default());
        let sidecar_volume = mesh_volume_name(&svc.sidecar);
        compose
            .volumes
            .entry(sidecar_volume.clone())
            .or_insert_with(EmptyMap::default);
        sidecar_service
            .volumes
            .push(format!("{sidecar_volume}:{MESH_CONFIG_DIR}:ro"));
        sidecar_service.depends_on = build_depends_on(
            false,
            vec![(
                PROVISIONER_SERVICE_NAME.to_string(),
                "service_completed_successfully",
            )],
        );
        compose
            .services
            .insert(svc.sidecar.clone(), sidecar_service);

        // depends_on: own sidecar + strong deps provider programs (+ amber-init for helper-backed services)
        let program_plan = program_plans.get(id).expect("program plan computed");
        let image = render_compose_image(program_plan.image(), &root_leaf_by_path)
            .map_err(DockerComposeError::Other)?;
        let mut program_service = Service::new(image);
        program_service.network_mode = Some(format!("service:{}", svc.sidecar));
        let label = component_label(s, *id);
        let mount_specs = config_plan.mount_specs.get(id).map(Vec::as_slice);
        let docker_mount_paths = docker_mount_paths_by_component.get(id);
        let has_docker_mount = docker_mount_paths.is_some_and(|paths| !paths.is_empty());
        let runtime_plan = build_component_runtime_plan(
            &label,
            program_plan,
            mount_specs,
            config_plan.runtime_views.get(id),
            has_docker_mount,
        )
        .map_err(dc_other)?;
        let mut deps: Vec<(String, &'static str)> = Vec::new();
        if any_helper && runtime_plan.needs_helper {
            deps.push((
                HELPER_INIT_SERVICE.to_string(),
                "service_completed_successfully",
            ));
        }
        deps.push((svc.sidecar.clone(), "service_started"));
        if let Some(ds) = mesh_plan.strong_deps.get(id) {
            for dep in ds {
                if let Some(dep_names) = names.get(dep) {
                    deps.push((dep_names.program.clone(), "service_started"));
                } else {
                    return Err(format!(
                        "internal error: missing service name for dependency {}",
                        component_label(s, *dep)
                    )
                    .into());
                }
            }
        }
        if docker_access_components.contains(id) {
            deps.push((DOCKER_GATEWAY_SERVICE_NAME.to_string(), "service_started"));
        }
        program_service.depends_on = build_depends_on(any_helper, deps);

        match runtime_plan.execution {
            ComponentExecutionPlan::Direct { entrypoint, env } => {
                // Use entrypoint so image entrypoints are ignored.
                let entrypoint = entrypoint
                    .iter()
                    .map(|a| escape_compose_interpolation(a).into_owned())
                    .collect::<Vec<_>>();
                program_service.entrypoint = Some(entrypoint);

                if !env.is_empty() {
                    let env_map = env
                        .iter()
                        .map(|(k, v)| (k.clone(), escape_compose_interpolation(v).into_owned()))
                        .collect::<BTreeMap<_, _>>();
                    program_service.environment = Some(Environment::Map(env_map));
                }
            }
            ComponentExecutionPlan::HelperRunner {
                direct_entrypoint_b64,
                direct_env_b64,
                template_spec_b64,
                runtime_config,
                mount_spec_b64,
            } => {
                configure_helper_runner_service(&mut program_service);

                let mut env_entries = Vec::new();
                if let Some(entrypoint_b64) = direct_entrypoint_b64 {
                    env_entries.push(format!("AMBER_DIRECT_ENTRYPOINT_B64={entrypoint_b64}"));
                }
                if let Some(env_b64) = direct_env_b64 {
                    env_entries.push(format!("AMBER_DIRECT_ENV_B64={env_b64}"));
                }
                if let Some(runtime_config) = runtime_config {
                    // Security: only expose root config leaves needed for used component paths.
                    let root_env_entries = build_root_env_entries(
                        root_leaves,
                        runtime_config.allowed_root_leaf_paths,
                    )?;
                    env_entries.extend(root_env_entries);
                    env_entries.push(format!(
                        "AMBER_ROOT_CONFIG_SCHEMA_B64={}",
                        runtime_config.root_schema_b64
                    ));
                    env_entries.push(format!(
                        "AMBER_COMPONENT_CONFIG_SCHEMA_B64={}",
                        runtime_config.component_schema_b64
                    ));
                    env_entries.push(format!(
                        "AMBER_COMPONENT_CONFIG_TEMPLATE_B64={}",
                        runtime_config.component_cfg_template_b64
                    ));
                }
                if let Some(template_spec_b64) = template_spec_b64 {
                    env_entries.push(format!("AMBER_TEMPLATE_SPEC_B64={template_spec_b64}"));
                }
                if let Some(mount_spec_b64) = mount_spec_b64 {
                    env_entries.push(format!("AMBER_MOUNT_SPEC_B64={mount_spec_b64}"));
                }
                if let Some(paths) = docker_mount_paths {
                    let local_proxy_port =
                        *docker_proxy_ports_by_component.get(id).ok_or_else(|| {
                            DockerComposeError::Other(format!(
                                "internal error: missing framework.docker proxy port for {}",
                                component_label(s, *id)
                            ))
                        })?;
                    let spec_b64 =
                        encode_docker_mount_proxy_spec_b64(paths, "127.0.0.1", local_proxy_port)?;
                    env_entries.push(format!("{DOCKER_MOUNT_PROXY_SPEC_ENV}={spec_b64}"));
                }
                program_service.environment = Some(Environment::List(env_entries));
            }
        }

        compose
            .services
            .insert(svc.program.clone(), program_service);
    }

    compose.networks.insert(
        MESH_NETWORK_NAME.to_string(),
        Network {
            driver: "bridge".to_string(),
        },
    );

    if needs_router {
        compose.x_amber = proxy_metadata;
    }

    serde_yaml::to_string(&compose).map_err(|e| {
        DockerComposeError::Other(format!("failed to serialize docker-compose yaml: {e}"))
    })
}

// ---- helpers ----

fn configure_helper_runner_service(service: &mut Service) {
    service
        .volumes
        .push(format!("{HELPER_VOLUME_NAME}:{HELPER_BIN_DIR}:ro"));
    service.entrypoint = Some(vec![HELPER_BIN_PATH.to_string(), "run".to_string()]);
}

fn collect_framework_docker_mount_paths(
    scenario: &Scenario,
    program_components: &[ComponentId],
) -> HashMap<ComponentId, Vec<String>> {
    let mut out = HashMap::new();
    for component in program_components {
        let Some(program) = scenario.component(*component).program.as_ref() else {
            continue;
        };
        let paths: Vec<String> = program
            .mounts
            .iter()
            .filter_map(|mount| match &mount.source {
                MountSource::Framework(name) if name.as_str() == "docker" => {
                    Some(mount.path.clone())
                }
                _ => None,
            })
            .collect();
        if !paths.is_empty() {
            out.insert(*component, paths);
        }
    }
    out
}

fn add_mount_only_framework_docker_bindings(
    mesh_plan: &mut MeshPlan,
    docker_mount_paths_by_component: &HashMap<ComponentId, Vec<String>>,
) {
    let already_bound: BTreeSet<ComponentId> = mesh_plan
        .framework_bindings
        .iter()
        .filter(|binding| binding.capability.as_str() == "docker")
        .map(|binding| binding.consumer)
        .collect();
    let docker_capability = FrameworkCapabilityName::try_from("docker")
        .expect("framework capability names are static and valid");

    let mut mount_components: Vec<ComponentId> =
        docker_mount_paths_by_component.keys().copied().collect();
    mount_components.sort_by_key(|component| component.0);
    for component in mount_components {
        if already_bound.contains(&component) {
            continue;
        }
        mesh_plan.framework_bindings.push(ResolvedFrameworkBinding {
            consumer: component,
            slot: INTERNAL_FRAMEWORK_DOCKER_SLOT.to_string(),
            capability: docker_capability.clone(),
            binding_name: None,
        });
    }
}

fn ensure_internal_framework_slot_ports(
    scenario: &Scenario,
    slot_ports_by_component: &mut HashMap<ComponentId, BTreeMap<String, u16>>,
    mesh_plan: &MeshPlan,
) -> DcResult<()> {
    let mut components = BTreeSet::new();
    for binding in &mesh_plan.framework_bindings {
        if binding.capability.as_str() == "docker" && binding.slot == INTERNAL_FRAMEWORK_DOCKER_SLOT
        {
            components.insert(binding.consumer);
        }
    }

    for component in components {
        let slot_ports = slot_ports_by_component.get_mut(&component).ok_or_else(|| {
            DockerComposeError::Other(format!(
                "internal error: missing local slot map for {}",
                component_label(scenario, component)
            ))
        })?;
        if slot_ports.contains_key(INTERNAL_FRAMEWORK_DOCKER_SLOT) {
            continue;
        }

        let mut reserved: HashSet<u16> = HashSet::new();
        let program = scenario
            .component(component)
            .program
            .as_ref()
            .expect("program component has program");
        if let Some(network) = program.network.as_ref() {
            for endpoint in &network.endpoints {
                reserved.insert(endpoint.port);
            }
        }
        for port in slot_ports.values() {
            reserved.insert(*port);
        }

        let mut next = LOCAL_SLOT_PORT_BASE;
        while reserved.contains(&next) {
            next = next.checked_add(1).ok_or_else(|| {
                DockerComposeError::Other(format!(
                    "ran out of local slot ports allocating for {}",
                    component_label(scenario, component)
                ))
            })?;
        }
        slot_ports.insert(INTERNAL_FRAMEWORK_DOCKER_SLOT.to_string(), next);
    }

    Ok(())
}

fn docker_proxy_ports_by_component(
    scenario: &Scenario,
    slot_ports_by_component: &HashMap<ComponentId, BTreeMap<String, u16>>,
    mesh_plan: &MeshPlan,
) -> DcResult<HashMap<ComponentId, u16>> {
    let mut ports = HashMap::new();
    for binding in &mesh_plan.framework_bindings {
        if binding.capability.as_str() != "docker" {
            continue;
        }
        if ports.contains_key(&binding.consumer) {
            continue;
        }
        let slot_ports = slot_ports_by_component
            .get(&binding.consumer)
            .ok_or_else(|| {
                DockerComposeError::Other(format!(
                    "internal error: missing local slot map for {}",
                    component_label(scenario, binding.consumer)
                ))
            })?;
        let listen_port = *slot_ports.get(&binding.slot).ok_or_else(|| {
            DockerComposeError::Other(format!(
                "internal error: missing local slot port for {}.{}",
                component_label(scenario, binding.consumer),
                binding.slot
            ))
        })?;
        ports.insert(binding.consumer, listen_port);
    }
    Ok(ports)
}

fn encode_docker_mount_proxy_spec_b64(
    paths: &[String],
    tcp_host: &str,
    tcp_port: u16,
) -> DcResult<String> {
    let specs: Vec<DockerMountProxySpec> = paths
        .iter()
        .map(|path| DockerMountProxySpec {
            path: path.clone(),
            tcp_host: tcp_host.to_string(),
            tcp_port,
        })
        .collect();
    let payload = serde_json::to_vec(&specs).map_err(|err| {
        DockerComposeError::Other(format!(
            "failed to serialize docker mount proxy specs: {err}"
        ))
    })?;
    Ok(base64::engine::general_purpose::STANDARD.encode(payload))
}

fn docker_gateway_depends_on(needs_router: bool) -> Vec<(String, &'static str)> {
    if needs_router {
        vec![(ROUTER_SERVICE_NAME.to_string(), "service_started")]
    } else {
        Vec::new()
    }
}

fn docker_gateway_service(
    image: &str,
    config_json: String,
    deps: Vec<(String, &'static str)>,
) -> Service {
    let mut service = Service::new(image);
    service
        .networks
        .insert(MESH_NETWORK_NAME.to_string(), EmptyMap::default());
    service.environment = Some(Environment::Map(BTreeMap::from([(
        DOCKER_GATEWAY_CONFIG_ENV.to_string(),
        config_json,
    )])));
    service.depends_on = build_depends_on(false, deps);
    service.volumes.push(format!(
        "${{{DOCKER_GATEWAY_HOST_SOCK_ENV}:-{}}}:{DOCKER_GATEWAY_CONTAINER_SOCK}",
        detect_default_host_docker_sock().display()
    ));
    service
}

fn build_docker_gateway_config_json() -> DcResult<String> {
    let callers = vec![DockerGatewayCallerConfig {
        host: ROUTER_SERVICE_NAME.to_string(),
        port: None,
        component: ROUTER_ID.to_string(),
        compose_service: ROUTER_SERVICE_NAME.to_string(),
    }];

    let config = DockerGatewayConfig {
        listen: format!("0.0.0.0:{DOCKER_GATEWAY_PORT}"),
        docker_sock: DOCKER_GATEWAY_CONTAINER_SOCK.to_string(),
        compose_project: "${COMPOSE_PROJECT_NAME}".to_string(),
        callers,
    };

    serde_json::to_string(&config).map_err(|err| {
        DockerComposeError::Other(format!("failed to serialize docker gateway config: {err}"))
    })
}

fn detect_default_host_docker_sock() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        // Docker Desktop exposes a bind-mountable daemon socket here.
        PathBuf::from("/var/run/docker.sock")
    }

    #[cfg(not(target_os = "macos"))]
    {
        if let Ok(host) = std::env::var("DOCKER_HOST")
            && let Some(path) = host.strip_prefix("unix://")
        {
            let candidate = PathBuf::from(path);
            if candidate.exists() {
                return candidate;
            }
        }

        if let Ok(home) = std::env::var("HOME") {
            let desktop = PathBuf::from(home).join(".docker/run/docker.sock");
            if desktop.exists() {
                return desktop;
            }
        }

        PathBuf::from("/var/run/docker.sock")
    }
}

fn build_root_env_entries(
    root_leaves: &[rc::SchemaLeaf],
    allowed_leaf_paths: &BTreeSet<String>,
) -> Result<Vec<String>, DockerComposeError> {
    let mut entries = Vec::new();
    for leaf in root_leaves {
        if !allowed_leaf_paths.contains(&leaf.path) {
            continue;
        }
        let var = rc::env_var_for_path(&leaf.path).map_err(|e| {
            DockerComposeError::Other(format!(
                "failed to map config path {} to env var: {e}",
                leaf.path
            ))
        })?;
        if leaf.required {
            entries.push(format!("{var}=${{{var}?missing config.{}}}", leaf.path));
        } else {
            entries.push(var);
        }
    }
    Ok(entries)
}

fn mesh_volume_name(service: &str) -> String {
    format!("{service}-mesh")
}

fn mesh_config_path() -> String {
    format!("{MESH_CONFIG_DIR}/{MESH_CONFIG_FILENAME}")
}

fn mesh_identity_path() -> String {
    format!("{MESH_CONFIG_DIR}/{MESH_IDENTITY_FILENAME}")
}

fn provisioner_mount_dir(service: &str) -> String {
    format!("{PROVISIONER_CONFIG_ROOT}/{service}")
}

fn build_depends_on(any_helper: bool, deps: Vec<(String, &'static str)>) -> Option<DependsOn> {
    if deps.is_empty() {
        return None;
    }
    let needs_conditions = any_helper || deps.iter().any(|(_, cond)| *cond != "service_started");
    if needs_conditions {
        let mut map = BTreeMap::new();
        for (name, cond) in deps {
            map.insert(
                name,
                DependsOnCondition {
                    condition: cond.to_string(),
                },
            );
        }
        Some(DependsOn::Conditions(map))
    } else {
        Some(DependsOn::List(
            deps.into_iter().map(|(name, _)| name).collect(),
        ))
    }
}

fn render_compose_image(
    image: &ProgramImagePlan,
    root_leaf_by_path: &BTreeMap<&str, &rc::SchemaLeaf>,
) -> Result<String, String> {
    match image {
        ProgramImagePlan::Static(value) => Ok(escape_compose_interpolation(value).into_owned()),
        ProgramImagePlan::RuntimeTemplate(parts) => {
            let mut rendered = String::new();
            for part in parts {
                match part {
                    ProgramImagePart::Literal(lit) => {
                        rendered.push_str(&escape_compose_interpolation(lit));
                    }
                    ProgramImagePart::RootConfigPath(path) => {
                        let leaf = root_leaf_by_path.get(path.as_str()).ok_or_else(|| {
                            format!(
                                "runtime program.image path config.{path} is not a root config \
                                 leaf"
                            )
                        })?;
                        let env_var = rc::env_var_for_path(path).map_err(|err| {
                            format!("failed to map config path {path} to env var: {err}")
                        })?;
                        if leaf.required {
                            rendered.push_str(&format!("${{{env_var}?missing config.{path}}}"));
                        } else {
                            rendered.push_str(&format!("${{{env_var}}}"));
                        }
                    }
                }
            }
            Ok(rendered)
        }
    }
}

fn service_base_name(id: ComponentId, local_name: &str) -> String {
    // Ensure injective via numeric prefix; keep human-readable suffix.
    let slug = sanitize_service_suffix(local_name);
    format!("c{}-{}", id.0, slug)
}

fn compose_control_socket_host_dir_expr(s: &Scenario) -> DcResult<String> {
    Ok(format!(
        "${{{}:-{}/{}}}/${{{}:-default}}",
        ROUTER_CONTROL_SOCKET_DIR_ENV,
        ROUTER_CONTROL_SOCKET_HOST_ROOT,
        scenario_socket_token(s)?,
        COMPOSE_PROJECT_NAME_ENV,
    ))
}

fn compose_control_socket_host_path_expr(s: &Scenario) -> DcResult<String> {
    Ok(format!(
        "{}/{}",
        compose_control_socket_host_dir_expr(s)?,
        ROUTER_CONTROL_SOCKET_FILENAME
    ))
}

fn scenario_socket_token(s: &Scenario) -> DcResult<String> {
    let digest = scenario_ir_digest(s)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..8]))
}

fn sanitize_service_suffix(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        let ch = ch.to_ascii_lowercase();
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    let out = out.trim_matches('-');
    if out.is_empty() {
        "component".to_string()
    } else {
        out.to_string()
    }
}

// NOTE: template interpolation is now handled structurally via `amber_manifest::InterpolatedString`
// parts and the runtime helper payload IR. The old string re-parser has been removed.

fn escape_compose_interpolation<'a>(line: &'a str) -> Cow<'a, str> {
    if line.contains('$') {
        Cow::Owned(line.replace('$', "$$"))
    } else {
        Cow::Borrowed(line)
    }
}

#[cfg(test)]
mod tests;
