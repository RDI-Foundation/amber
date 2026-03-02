use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashMap},
    path::PathBuf,
};

use amber_config as rc;
use amber_manifest::MountSource;
use amber_mesh::{
    MESH_CONFIG_FILENAME, MESH_IDENTITY_FILENAME, MESH_PROVISION_PLAN_VERSION, MeshProvisionOutput,
    MeshProvisionPlan, MeshProvisionTarget, MeshProvisionTargetKind,
};
use amber_scenario::{ComponentId, Scenario};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::{
    CompileOutput,
    reporter::{Reporter, ReporterError},
    targets::mesh::{
        addressing::{Addressing, build_address_plan},
        config::{
            ProgramImagePart, ProgramImagePlan, ProgramPlan, build_config_plan,
            encode_component_payload, encode_direct_entrypoint_b64, encode_direct_env_b64,
            encode_helper_payload, encode_mount_spec_b64, encode_schema_b64,
            mount_specs_need_config,
        },
        internal_images::resolve_internal_images,
        mesh_config::{
            MeshAddressing, MeshConfigPlan, RouterPorts, build_mesh_config_plan, scenario_ir_digest,
        },
        plan::{
            MeshError, MeshOptions, ResolvedBinding, ResolvedExternalBinding,
            ResolvedFrameworkBinding, component_label,
        },
        ports::{allocate_mesh_ports, allocate_slot_ports},
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

struct ComposeAddressing<'a> {
    scenario: &'a Scenario,
    slot_ports_by_component: HashMap<ComponentId, BTreeMap<String, u16>>,
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

impl<'a> ComposeAddressing<'a> {
    fn new(
        scenario: &'a Scenario,
        slot_ports_by_component: HashMap<ComponentId, BTreeMap<String, u16>>,
    ) -> Result<Self, DockerComposeError> {
        Ok(Self {
            scenario,
            slot_ports_by_component,
        })
    }

    fn local_proxy_port(
        &self,
        component: ComponentId,
        slot: &str,
    ) -> Result<u16, DockerComposeError> {
        self.slot_ports_by_component
            .get(&component)
            .and_then(|ports| ports.get(slot))
            .copied()
            .ok_or_else(|| {
                DockerComposeError::Other(format!(
                    "internal error: missing local port allocation for {}.{}",
                    component_label(self.scenario, component),
                    slot
                ))
            })
    }
}

impl Addressing for ComposeAddressing<'_> {
    type Error = DockerComposeError;

    fn resolve_binding_url(&mut self, binding: &ResolvedBinding) -> Result<String, Self::Error> {
        let local_port = self.local_proxy_port(binding.consumer, &binding.slot)?;

        Ok(format!("http://127.0.0.1:{local_port}"))
    }

    fn resolve_external_binding_url(
        &mut self,
        binding: &ResolvedExternalBinding,
    ) -> Result<String, Self::Error> {
        let local_port = self.local_proxy_port(binding.consumer, &binding.slot)?;

        Ok(format!("http://127.0.0.1:{local_port}"))
    }
    fn resolve_framework_binding_url(
        &mut self,
        binding: &ResolvedFrameworkBinding,
    ) -> Result<String, Self::Error> {
        if binding.capability.as_str() != "docker" {
            return Err(DockerComposeError::Other(format!(
                "docker-compose reporter does not support framework capability `framework.{}`",
                binding.capability
            )));
        }
        Ok(format!(
            "tcp://{DOCKER_GATEWAY_SERVICE_NAME}:{DOCKER_GATEWAY_PORT}"
        ))
    }
}

fn render_docker_compose(output: &CompileOutput) -> Result<String, ReporterError> {
    render_docker_compose_inner(output).map_err(|err| err.into_reporter_error(output))
}

fn render_docker_compose_inner(output: &CompileOutput) -> DcResult<String> {
    let s = &output.scenario;

    let mesh_plan = crate::targets::mesh::plan::build_mesh_plan(
        s,
        &output.store,
        MeshOptions {
            backend_label: "docker-compose reporter",
        },
    )
    .map_err(dc_other)?;
    let images = resolve_internal_images().map_err(DockerComposeError::Other)?;

    let program_components = mesh_plan.program_components.as_slice();

    // Precompute service names (injective & stable).
    let mut names: HashMap<ComponentId, ServiceNames> = HashMap::new();
    for id in program_components {
        let c = s.component(*id);
        let base = service_base_name(*id, c.moniker.local_name().unwrap_or("component"));
        let sidecar = format!("{base}-net");
        names.insert(
            *id,
            ServiceNames {
                program: base,
                sidecar,
            },
        );
    }
    let root_manifest = mesh_plan.manifests[s.root.0]
        .as_ref()
        .expect("root manifest should exist");

    let needs_router = !mesh_plan.external_bindings.is_empty() || !mesh_plan.exports.is_empty();

    let slot_ports_by_component = allocate_slot_ports(s, program_components)?;
    let mesh_ports_by_component = allocate_mesh_ports(
        s,
        program_components,
        COMPONENT_MESH_PORT_BASE,
        &slot_ports_by_component,
    )?;
    let docker_mount_paths_by_component =
        collect_framework_docker_mount_paths(s, program_components);
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
    let router_ports = needs_router.then_some(RouterPorts {
        mesh: ROUTER_MESH_PORT_BASE,
        control: ROUTER_CONTROL_PORT_BASE,
    });

    let addressing = ComposeAddressing::new(s, slot_ports_by_component.clone())?;
    let address_plan = build_address_plan(&mesh_plan, addressing)?;

    struct ComposeMeshAddressing<'a> {
        names: &'a HashMap<ComponentId, ServiceNames>,
        mesh_ports_by_component: &'a HashMap<ComponentId, u16>,
        router_mesh_port: u16,
    }

    impl MeshAddressing for ComposeMeshAddressing<'_> {
        fn mesh_addr_for_component(&self, id: ComponentId) -> Result<String, MeshError> {
            let svc = self.names.get(&id).ok_or_else(|| {
                MeshError::new(format!("missing service name for component {id:?}"))
            })?;
            let port = *self
                .mesh_ports_by_component
                .get(&id)
                .ok_or_else(|| MeshError::new(format!("missing mesh port for component {id:?}")))?;
            Ok(format!("{}:{}", svc.sidecar, port))
        }

        fn mesh_addr_for_router(&self) -> Result<String, MeshError> {
            Ok(format!("{ROUTER_SERVICE_NAME}:{}", self.router_mesh_port))
        }
    }

    let router_mesh_port = router_ports
        .as_ref()
        .map(|ports| ports.mesh)
        .unwrap_or(ROUTER_MESH_PORT_BASE);
    let mesh_addressing = ComposeMeshAddressing {
        names: &names,
        mesh_ports_by_component: &mesh_ports_by_component,
        router_mesh_port,
    };
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
    let mesh_provision_plan = build_provision_plan(&mesh_config_plan, program_components, &names)
        .map_err(|err| DockerComposeError::Other(err.to_string()))?;
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
        let gateway_deps = docker_gateway_depends_on(s, &docker_access_components, &names)?;
        let gateway_service = docker_gateway_service(
            &images.docker_gateway,
            build_docker_gateway_config_json(s, &docker_access_components, &names)?,
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
        let mount_specs = config_plan.mount_specs.get(id);
        let docker_mount_paths = docker_mount_paths_by_component.get(id);
        let has_docker_mount = docker_mount_paths.is_some_and(|paths| !paths.is_empty());
        let mounts_need_config = mount_specs.is_some_and(|specs| mount_specs_need_config(specs));
        let needs_config_payload =
            matches!(program_plan, ProgramPlan::Helper { .. }) || mounts_need_config;
        let needs_helper_for_component = matches!(program_plan, ProgramPlan::Helper { .. })
            || mount_specs.is_some()
            || has_docker_mount;
        let runtime_view = needs_config_payload.then(|| {
            config_plan
                .runtime_views
                .get(id)
                .expect("runtime config view should be computed")
        });
        let mut deps: Vec<(String, &'static str)> = Vec::new();
        if any_helper && needs_helper_for_component {
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

        let append_runtime_config_env = |env_entries: &mut Vec<String>,
                                         component_schema_b64: &str,
                                         component_template_b64: &str|
         -> Result<(), DockerComposeError> {
            let view = runtime_view.expect("runtime config view should be computed");
            let root_schema_b64 = encode_schema_b64(
                &format!("root config definition for {label}"),
                &view.pruned_root_schema,
            )
            .map_err(dc_other)?;
            let root_env_entries =
                build_root_env_entries(root_leaves, &view.allowed_root_leaf_paths)?;
            env_entries.extend(root_env_entries);
            env_entries.push(format!("AMBER_ROOT_CONFIG_SCHEMA_B64={root_schema_b64}"));
            env_entries.push(format!(
                "AMBER_COMPONENT_CONFIG_SCHEMA_B64={component_schema_b64}"
            ));
            env_entries.push(format!(
                "AMBER_COMPONENT_CONFIG_TEMPLATE_B64={component_template_b64}"
            ));
            Ok(())
        };

        let append_mount_and_proxy_env =
            |env_entries: &mut Vec<String>| -> Result<(), DockerComposeError> {
                if let Some(specs) = mount_specs {
                    let mount_b64 = encode_mount_spec_b64(&label, specs).map_err(dc_other)?;
                    env_entries.push(format!("AMBER_MOUNT_SPEC_B64={mount_b64}"));
                }
                if let Some(paths) = docker_mount_paths {
                    let spec_b64 = encode_docker_mount_proxy_spec_b64(paths)?;
                    env_entries.push(format!("{DOCKER_MOUNT_PROXY_SPEC_ENV}={spec_b64}"));
                }
                Ok(())
            };

        match program_plan {
            ProgramPlan::Direct {
                entrypoint, env, ..
            } if !needs_helper_for_component => {
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
            ProgramPlan::Direct {
                entrypoint, env, ..
            } => {
                let entrypoint_b64 = encode_direct_entrypoint_b64(entrypoint).map_err(dc_other)?;
                let env_b64 = encode_direct_env_b64(env).map_err(dc_other)?;

                configure_helper_runner_service(&mut program_service);

                let mut env_entries = Vec::new();
                env_entries.push(format!("AMBER_DIRECT_ENTRYPOINT_B64={entrypoint_b64}"));
                env_entries.push(format!("AMBER_DIRECT_ENV_B64={env_b64}"));

                if needs_config_payload {
                    let view = runtime_view.expect("runtime config view should be computed");
                    let payload = encode_component_payload(
                        &label,
                        &view.component_template,
                        &view.component_schema,
                    )
                    .map_err(dc_other)?;
                    append_runtime_config_env(
                        &mut env_entries,
                        &payload.component_schema_b64,
                        &payload.component_cfg_template_b64,
                    )?;
                }

                append_mount_and_proxy_env(&mut env_entries)?;

                program_service.environment = Some(Environment::List(env_entries));
            }
            ProgramPlan::Helper { template_spec, .. } => {
                let view = runtime_view.expect("runtime config view should be computed");
                let payload = encode_helper_payload(
                    &label,
                    template_spec,
                    &view.component_template,
                    &view.component_schema,
                )
                .map_err(dc_other)?;

                configure_helper_runner_service(&mut program_service);

                // Security: only expose root config leaves needed for the used component paths.
                let mut env_entries = Vec::new();
                append_runtime_config_env(
                    &mut env_entries,
                    &payload.component_schema_b64,
                    &payload.component_cfg_template_b64,
                )?;
                env_entries.push(format!(
                    "AMBER_TEMPLATE_SPEC_B64={}",
                    payload.template_spec_b64
                ));
                append_mount_and_proxy_env(&mut env_entries)?;
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

fn encode_docker_mount_proxy_spec_b64(paths: &[String]) -> DcResult<String> {
    let specs: Vec<DockerMountProxySpec> = paths
        .iter()
        .map(|path| DockerMountProxySpec {
            path: path.clone(),
            tcp_host: DOCKER_GATEWAY_SERVICE_NAME.to_string(),
            tcp_port: DOCKER_GATEWAY_PORT,
        })
        .collect();
    let payload = serde_json::to_vec(&specs).map_err(|err| {
        DockerComposeError::Other(format!(
            "failed to serialize docker mount proxy specs: {err}"
        ))
    })?;
    Ok(base64::engine::general_purpose::STANDARD.encode(payload))
}

fn docker_gateway_depends_on(
    scenario: &Scenario,
    docker_access_components: &BTreeSet<ComponentId>,
    names: &HashMap<ComponentId, ServiceNames>,
) -> DcResult<Vec<(String, &'static str)>> {
    let mut deps = Vec::with_capacity(docker_access_components.len());
    for component in docker_access_components {
        let service_names = names.get(component).ok_or_else(|| {
            DockerComposeError::Other(format!(
                "internal error: missing service names for {}",
                component_label(scenario, *component)
            ))
        })?;
        deps.push((service_names.sidecar.clone(), "service_started"));
    }
    Ok(deps)
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

fn build_docker_gateway_config_json(
    scenario: &Scenario,
    docker_access_components: &BTreeSet<ComponentId>,
    names: &HashMap<ComponentId, ServiceNames>,
) -> DcResult<String> {
    let callers = docker_access_components
        .iter()
        .map(|component| {
            let service_names = names.get(component).ok_or_else(|| {
                DockerComposeError::Other(format!(
                    "internal error: missing service names for {}",
                    component_label(scenario, *component)
                ))
            })?;
            Ok(DockerGatewayCallerConfig {
                host: service_names.sidecar.clone(),
                port: None,
                component: component_label(scenario, *component),
                compose_service: service_names.program.clone(),
            })
        })
        .collect::<DcResult<Vec<_>>>()?;

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

fn build_provision_plan(
    mesh_config_plan: &MeshConfigPlan,
    program_components: &[ComponentId],
    names: &HashMap<ComponentId, ServiceNames>,
) -> Result<MeshProvisionPlan, String> {
    let mut targets = Vec::new();
    for id in program_components {
        let svc = names
            .get(id)
            .ok_or_else(|| format!("missing service name for component {id:?}"))?;
        let template = mesh_config_plan
            .component_configs
            .get(id)
            .ok_or_else(|| format!("missing config template for component {id:?}"))?
            .clone();
        targets.push(MeshProvisionTarget {
            kind: MeshProvisionTargetKind::Component,
            config: template,
            output: MeshProvisionOutput::Filesystem {
                dir: provisioner_mount_dir(&svc.sidecar),
            },
        });
    }
    if let Some(router_template) = mesh_config_plan.router_config.as_ref() {
        let mut router_template = router_template.clone();
        router_template.control_listen = None;
        router_template.control_allow = None;
        targets.push(MeshProvisionTarget {
            kind: MeshProvisionTargetKind::Router,
            config: router_template,
            output: MeshProvisionOutput::Filesystem {
                dir: provisioner_mount_dir(ROUTER_SERVICE_NAME),
            },
        });
    }
    Ok(MeshProvisionPlan {
        version: MESH_PROVISION_PLAN_VERSION.to_string(),
        targets,
    })
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
