use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
    ops::Deref,
    path::{Path, PathBuf},
};

use amber_config as rc;
use amber_mesh::{MESH_CONFIG_FILENAME, MESH_IDENTITY_FILENAME, MeshProvisionOutput};
use amber_scenario::{ComponentId, ProgramMount, Scenario};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

mod framework_docker_injection;

use framework_docker_injection::{
    FRAMEWORK_DOCKER_GATEWAY_PORT, rewrite_framework_docker_as_injected_component,
};

use crate::{
    config::analysis::ScenarioConfigAnalysis,
    reporter::{
        CompiledScenario, Reporter, ReporterError,
        execution_guide::{
            GENERATED_COMPOSE_FILENAME, GENERATED_ENV_SAMPLE_FILENAME, GENERATED_README_FILENAME,
            build_execution_guide,
        },
    },
    runtime_interface::{RootInputDescriptor, collect_root_inputs},
    targets::{
        mesh::{
            addressing::{
                DockerFrameworkBindingPolicy, LocalAddressing, LocalAddressingOptions,
                build_address_plan,
            },
            internal_images::resolve_internal_images,
            mesh_config::{
                MeshConfigBuildInput, MeshServiceName, RouterPorts, ServiceMeshAddressing,
                build_mesh_config_plan, default_mesh_config_build_options,
            },
            plan::{MeshOptions, component_label, map_program_components},
            ports::{LocalRoutePorts, allocate_local_route_ports, allocate_mesh_ports},
            provision::build_mesh_provision_plan,
            proxy_metadata::{ProxyMetadata, RouterMetadata, build_proxy_metadata},
        },
        program_config::{
            ComponentExecutionPlan, ProgramImagePart, ProgramImagePlan, ProgramSupport,
            build_component_runtime_plan, build_config_plan,
        },
        storage::{StorageIdentity, build_storage_plan},
    },
};

const MESH_NETWORK_NAME: &str = "amber_mesh";

const ROUTER_SERVICE_NAME: &str = "amber-router";
const ROUTER_CONTROL_INIT_SERVICE_NAME: &str = "amber-router-control-init";
const PROVISIONER_SERVICE_NAME: &str = "amber-provisioner";
const HELPER_VOLUME_NAME: &str = "amber-helper-bin";
const HELPER_INIT_SERVICE: &str = "amber-init";
const HELPER_BIN_DIR: &str = "/amber/bin";
const HELPER_BIN_PATH: &str = "/amber/bin/amber-helper";
const DOCKER_MOUNT_PROXY_SPEC_ENV: &str = "AMBER_DOCKER_MOUNT_PROXY_SPEC_B64";
const DOCKER_GATEWAY_CONFIG_ENV: &str = "AMBER_DOCKER_GATEWAY_CONFIG_JSON";
const DOCKER_GATEWAY_HOST_SOCK_ENV: &str = "AMBER_DOCKER_SOCK";
const DOCKER_GATEWAY_CONTAINER_SOCK: &str = "/var/run/docker.sock";
const MESH_CONFIG_DIR: &str = "/amber/mesh";
const PROVISIONER_CONFIG_ROOT: &str = "/amber/provision";
const PROVISIONER_PLAN_CONFIG_NAME: &str = "amber-mesh-provision-plan";
const PROVISIONER_PLAN_PATH: &str = "/amber/plan/mesh-provision-plan.json";
const HOST_GATEWAY_ENTRY: &str = "host.docker.internal:host-gateway";
const ROUTER_CONTROL_SOCKET_VOLUME_NAME: &str = "amber-router-control";
const ROUTER_CONTROL_SOCKET_PATH_IN_CONTAINER: &str = "/amber/control/router-control.sock";
const ROUTER_CONTROL_SOCKET_DIR_IN_CONTAINER: &str = "/amber/control";
const ROUTER_CONTROL_SOCKET_PATH_IN_VOLUME: &str = "/router-control.sock";
const COMPOSE_PROJECT_NAME_ENV: &str = "COMPOSE_PROJECT_NAME";
const SCENARIO_RUN_ID_ENV: &str = "AMBER_SCENARIO_RUN_ID";
const ROUTER_RUNTIME_UID: u32 = 65532;
const ROUTER_RUNTIME_GID: u32 = 65532;

const COMPONENT_MESH_PORT_BASE: u16 = 23000;
const ROUTER_MESH_PORT_BASE: u16 = 24000;
const ROUTER_CONTROL_PORT_BASE: u16 = 24100;

const OTELCOL_SERVICE_NAME: &str = "amber-otelcol";
const OTELCOL_CONFIG_NAME: &str = "amber-otelcol-config";
const OTELCOL_CONFIG_PATH: &str = "/etc/otelcol/config.yaml";
const OTELCOL_UPSTREAM_ENV: &str = "AMBER_OTEL_UPSTREAM_OTLP_HTTP_ENDPOINT";
const OTELCOL_DEFAULT_UPSTREAM_ENDPOINT: &str = "http://host.docker.internal:18890";
const DEFAULT_OTELCOL_IMAGE: &str = "otel/opentelemetry-collector-contrib:0.143.0";
const ROUTER_OTLP_ENDPOINT: &str = "http://amber-otelcol:4318";
const DOCKER_CONTAINER_LOGS_DIR: &str = "/var/lib/docker/containers";
const LOG_LABEL_MONIKER: &str = "amber_component_moniker";
const LOG_LABEL_SERVICE_NAME: &str = "amber_service_name";
const LOG_LABEL_LIST: &str = "amber_component_moniker,amber_service_name";
pub const COMPOSE_FILENAME: &str = GENERATED_COMPOSE_FILENAME;

#[derive(Clone, Copy, Debug, Default)]
pub struct DockerComposeReporter;

#[derive(Clone, Debug)]
pub struct DockerComposeArtifact {
    pub files: BTreeMap<PathBuf, String>,
}

impl DockerComposeArtifact {
    pub fn compose_yaml(&self) -> &str {
        self.files
            .get(Path::new(GENERATED_COMPOSE_FILENAME))
            .expect("compose artifact should include compose.yaml")
    }
}

impl fmt::Display for DockerComposeArtifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.compose_yaml())
    }
}

impl Deref for DockerComposeArtifact {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.compose_yaml()
    }
}

impl AsRef<str> for DockerComposeArtifact {
    fn as_ref(&self) -> &str {
        self.compose_yaml()
    }
}

impl AsRef<[u8]> for DockerComposeArtifact {
    fn as_ref(&self) -> &[u8] {
        self.compose_yaml().as_bytes()
    }
}

impl Reporter for DockerComposeReporter {
    type Artifact = DockerComposeArtifact;

    fn emit(&self, compiled: &CompiledScenario) -> Result<Self::Artifact, ReporterError> {
        render_docker_compose(compiled)
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
    logging: Option<ServiceLogging>,
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
struct ServiceLogging {
    driver: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    options: BTreeMap<String, String>,
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

impl From<crate::targets::common::TargetError> for DockerComposeError {
    fn from(value: crate::targets::common::TargetError) -> Self {
        Self::Other(value.to_string())
    }
}

fn dc_other(err: impl ToString) -> DockerComposeError {
    DockerComposeError::Other(err.to_string())
}

impl DockerComposeError {
    fn into_reporter_error(self) -> ReporterError {
        match self {
            DockerComposeError::Other(message) => ReporterError::new(message),
        }
    }
}

type DcResult<T> = Result<T, DockerComposeError>;

fn render_docker_compose(
    compiled: &CompiledScenario,
) -> Result<DockerComposeArtifact, ReporterError> {
    render_docker_compose_inner(compiled.scenario())
        .map_err(DockerComposeError::into_reporter_error)
}

fn render_docker_compose_inner(scenario: &Scenario) -> DcResult<DockerComposeArtifact> {
    let transformed = rewrite_framework_docker_as_injected_component(scenario).map_err(dc_other)?;
    let s = &transformed.scenario;
    let endpoint_plan = crate::targets::program_config::build_endpoint_plan(s).map_err(dc_other)?;

    let mesh_plan = crate::targets::mesh::plan::build_mesh_plan(
        s,
        &endpoint_plan,
        MeshOptions {
            backend_label: "docker-compose reporter",
        },
    )
    .map_err(dc_other)?;
    let images = resolve_internal_images().map_err(DockerComposeError::Other)?;
    let docker_mount_paths_by_component =
        collect_framework_docker_mount_paths(s, mesh_plan.program_components());
    let program_components = mesh_plan.program_components();
    let storage_plan = build_storage_plan(s, program_components);
    // Precompute service names (injective & stable).
    let names: HashMap<ComponentId, ServiceNames> =
        map_program_components(s, program_components, |id, local_name| {
            let base = service_base_name(id, local_name);
            ServiceNames {
                program: base.clone(),
                sidecar: format!("{base}-net"),
            }
        });
    let docker_mount_components: BTreeSet<ComponentId> =
        docker_mount_paths_by_component.keys().copied().collect();
    let docker_gateway_component = transformed.gateway_component;
    let needs_router = mesh_plan.needs_router();

    let route_ports = allocate_local_route_ports(s, &endpoint_plan, &mesh_plan)?;
    let mesh_ports_by_component = allocate_mesh_ports(
        s,
        &endpoint_plan,
        program_components,
        COMPONENT_MESH_PORT_BASE,
        &route_ports,
    )?;
    let docker_proxy_ports_by_component =
        docker_proxy_ports_by_component(s, &route_ports, &transformed.proxy_slot_by_component)?;
    let router_ports = needs_router.then_some(RouterPorts {
        mesh: ROUTER_MESH_PORT_BASE,
        control: ROUTER_CONTROL_PORT_BASE,
    });

    let addressing = LocalAddressing::new(
        s,
        &route_ports,
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
    let mesh_config_plan = build_mesh_config_plan(MeshConfigBuildInput {
        scenario: s,
        mesh_plan: &mesh_plan,
        route_ports: &route_ports,
        mesh_ports_by_component: &mesh_ports_by_component,
        router_ports,
        addressing: &mesh_addressing,
        options: default_mesh_config_build_options(),
    })
    .map_err(|err| DockerComposeError::Other(err.to_string()))?;
    let router_metadata = if needs_router {
        Some(RouterMetadata {
            mesh_port: router_mesh_port,
            control_port: router_ports.as_ref().expect("router ports missing").control,
            control_socket: Some(ROUTER_CONTROL_SOCKET_PATH_IN_VOLUME.to_string()),
            control_socket_volume: Some(compose_control_socket_volume_expr()),
        })
    } else {
        None
    };
    let proxy_metadata =
        needs_router.then_some(build_proxy_metadata(s, &mesh_plan, router_metadata));
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
    let config_analysis = ScenarioConfigAnalysis::from_scenario(s).map_err(dc_other)?;

    // Compose YAML
    // ---- runtime config / helper decision ----
    let config_plan = build_config_plan(
        s,
        &config_analysis,
        program_components,
        ProgramSupport::Image {
            backend_label: "docker-compose output",
        },
        crate::targets::program_config::RuntimeAddressResolution::Static,
        &address_plan.slot_values_by_component,
    )
    .map_err(dc_other)?;

    let root_leaves = &config_plan.root_leaves;
    let root_inputs = collect_root_inputs(&config_plan)
        .map_err(|err| DockerComposeError::Other(err.to_string()))?;
    let root_leaf_by_path: BTreeMap<&str, &rc::SchemaLeaf> = root_leaves
        .iter()
        .map(|leaf| (leaf.path.as_str(), leaf))
        .collect();
    let program_plans = &config_plan.program_plans;
    let any_helper = config_plan.needs_helper || !docker_mount_components.is_empty();

    let mut compose = DockerComposeFile::default();

    for mounts in storage_plan.mounts_by_component.values() {
        for mount in mounts {
            compose
                .volumes
                .entry(compose_storage_volume_name(&mount.identity))
                .or_insert_with(EmptyMap::default);
        }
    }

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

    // Per-scenario OpenTelemetry collector agent.
    //
    // Amber runtimes export OTLP traces and logs directly to the collector, which then forwards
    // them to the configured upstream endpoint (defaulting to the local `amber dashboard` Aspire
    // OTLP/HTTP port).
    let otelcol_config = otelcol_config_content();
    compose.configs.insert(
        OTELCOL_CONFIG_NAME.to_string(),
        ComposeConfig {
            content: otelcol_config,
        },
    );
    let mut otelcol_service =
        Service::new(format!("${{AMBER_OTELCOL_IMAGE:-{DEFAULT_OTELCOL_IMAGE}}}"));
    otelcol_service.command = Some(vec![format!("--config={OTELCOL_CONFIG_PATH}")]);
    otelcol_service.user = Some("0:0".to_string());
    otelcol_service.environment = Some(Environment::List(vec![
        format!("{SCENARIO_RUN_ID_ENV}=${{{COMPOSE_PROJECT_NAME_ENV}:-default}}"),
        format!(
            "{OTELCOL_UPSTREAM_ENV}=${{{OTELCOL_UPSTREAM_ENV}:\
             -{OTELCOL_DEFAULT_UPSTREAM_ENDPOINT}}}"
        ),
    ]));
    otelcol_service.configs.push(ServiceConfigMount {
        source: OTELCOL_CONFIG_NAME.to_string(),
        target: Some(OTELCOL_CONFIG_PATH.to_string()),
    });
    otelcol_service
        .networks
        .insert(MESH_NETWORK_NAME.to_string(), EmptyMap::default());
    otelcol_service
        .extra_hosts
        .push(HOST_GATEWAY_ENTRY.to_string());
    otelcol_service.volumes.push(format!(
        "${{AMBER_DOCKER_CONTAINER_LOGS_DIR:-{DOCKER_CONTAINER_LOGS_DIR}}}:\
         {DOCKER_CONTAINER_LOGS_DIR}:ro"
    ));
    compose
        .services
        .insert(OTELCOL_SERVICE_NAME.to_string(), otelcol_service);

    if needs_router {
        compose
            .volumes
            .entry(ROUTER_CONTROL_SOCKET_VOLUME_NAME.to_string())
            .or_insert_with(EmptyMap::default);

        let mut control_init_service = Service::new("busybox:1.36.1".to_string());
        control_init_service.user = Some("0:0".to_string());
        control_init_service.command = Some(vec![
            "sh".to_string(),
            "-lc".to_string(),
            format!(
                "mkdir -p {ROUTER_CONTROL_SOCKET_DIR_IN_CONTAINER} && chown \
                 {ROUTER_RUNTIME_UID}:{ROUTER_RUNTIME_GID} \
                 {ROUTER_CONTROL_SOCKET_DIR_IN_CONTAINER} && chmod 0700 \
                 {ROUTER_CONTROL_SOCKET_DIR_IN_CONTAINER}"
            ),
        ]);
        control_init_service.volumes.push(format!(
            "{ROUTER_CONTROL_SOCKET_VOLUME_NAME}:{ROUTER_CONTROL_SOCKET_DIR_IN_CONTAINER}"
        ));
        control_init_service.restart = Some("no".to_string());
        compose.services.insert(
            ROUTER_CONTROL_INIT_SERVICE_NAME.to_string(),
            control_init_service,
        );

        let mut env_entries = mesh_config_plan.router_env_passthrough.clone();
        env_entries.push(format!("AMBER_ROUTER_CONFIG_PATH={}", mesh_config_path()));
        env_entries.push(format!(
            "AMBER_ROUTER_IDENTITY_PATH={}",
            mesh_identity_path()
        ));
        env_entries.push(format!(
            "AMBER_ROUTER_CONTROL_SOCKET_PATH={ROUTER_CONTROL_SOCKET_PATH_IN_CONTAINER}"
        ));
        push_router_observability_env(&mut env_entries);
        let mut router_service = Service::new(images.router.clone());
        router_service.environment = Some(Environment::List(env_entries));
        router_service
            .extra_hosts
            .push(HOST_GATEWAY_ENTRY.to_string());
        router_service
            .networks
            .insert(MESH_NETWORK_NAME.to_string(), EmptyMap::default());
        if !exports_by_name.is_empty() {
            router_service
                .ports
                .push(format!("127.0.0.1::{router_mesh_port}"));
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
            "{ROUTER_CONTROL_SOCKET_VOLUME_NAME}:{ROUTER_CONTROL_SOCKET_DIR_IN_CONTAINER}"
        ));
        router_service.depends_on = build_depends_on(
            false,
            vec![
                (
                    PROVISIONER_SERVICE_NAME.to_string(),
                    "service_completed_successfully",
                ),
                (
                    ROUTER_CONTROL_INIT_SERVICE_NAME.to_string(),
                    "service_completed_successfully",
                ),
            ],
        );

        compose
            .services
            .insert(ROUTER_SERVICE_NAME.to_string(), router_service);
    }

    // Emit services in stable (component id) order, sidecar then program.
    for id in program_components {
        let svc = names.get(id).unwrap();

        let mut sidecar_service = Service::new(images.router.clone());
        let mut sidecar_env_entries = vec![
            format!("AMBER_ROUTER_CONFIG_PATH={}", mesh_config_path()),
            format!("AMBER_ROUTER_IDENTITY_PATH={}", mesh_identity_path()),
        ];
        push_router_observability_env(&mut sidecar_env_entries);
        sidecar_service.environment = Some(Environment::List(sidecar_env_entries));
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
        let image = if Some(*id) == docker_gateway_component {
            images.docker_gateway.clone()
        } else {
            let image_plan = program_plan.image().ok_or_else(|| {
                DockerComposeError::Other(format!(
                    "internal error: {} is missing a container image plan",
                    component_label(s, *id)
                ))
            })?;
            render_compose_image(image_plan, &root_leaf_by_path)
                .map_err(DockerComposeError::Other)?
        };
        let mut program_service = Service::new(image);
        program_service.network_mode = Some(format!("service:{}", svc.sidecar));
        let label = component_label(s, *id);
        let storage_mounts = storage_plan
            .mounts_by_component
            .get(id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let scenario_scope = mesh_config_plan
            .component_configs
            .get(id)
            .and_then(|config| config.identity.mesh_scope.as_deref());
        let mount_specs = config_plan.mount_specs.get(id).map(Vec::as_slice);
        let docker_mount_paths = docker_mount_paths_by_component.get(id);
        let has_docker_mount = docker_mount_paths.is_some_and(|paths| !paths.is_empty());
        let runtime_plan = build_component_runtime_plan(
            &label,
            program_plan,
            mount_specs,
            config_plan.runtime_views.get(id),
            has_docker_mount,
            false,
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
        if let Some(ds) = mesh_plan.strong_deps().get(id) {
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
        program_service.depends_on = build_depends_on(any_helper, deps);

        match runtime_plan.execution {
            ComponentExecutionPlan::Resolved { entrypoint, env } => {
                // Use entrypoint so image entrypoints are ignored.
                let entrypoint = entrypoint
                    .iter()
                    .map(|a| escape_compose_interpolation(a).into_owned())
                    .collect::<Vec<_>>();
                program_service.entrypoint = Some(entrypoint);

                let mut env_map = env
                    .iter()
                    .map(|(k, v)| (k.clone(), escape_compose_interpolation(v).into_owned()))
                    .collect::<BTreeMap<_, _>>();
                push_program_observability_env_map(&mut env_map, &label, scenario_scope);
                if !env_map.is_empty() {
                    program_service.environment = Some(Environment::Map(env_map));
                }
            }
            ComponentExecutionPlan::HelperRunner {
                entrypoint_b64,
                env_b64,
                template_spec_b64,
                runtime_config,
                mount_spec_b64,
            } => {
                configure_helper_runner_service(&mut program_service);

                let mut env_entries = Vec::new();
                if let Some(entrypoint_b64) = entrypoint_b64 {
                    env_entries.push(format!("AMBER_RESOLVED_ENTRYPOINT_B64={entrypoint_b64}"));
                }
                if let Some(env_b64) = env_b64 {
                    env_entries.push(format!("AMBER_RESOLVED_ENV_B64={env_b64}"));
                }
                if let Some(runtime_config) = runtime_config {
                    // Security: only expose root config leaves needed for used component paths.
                    let root_env_entries = build_root_env_entries(
                        &root_inputs,
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
                push_program_observability_env(&mut env_entries, &label, scenario_scope);
                program_service.environment = Some(Environment::List(env_entries));
            }
        }
        if Some(*id) == docker_gateway_component {
            configure_injected_docker_gateway_service(&mut program_service, s, *id, svc)?;
        }
        for storage_mount in storage_mounts {
            program_service.volumes.push(format!(
                "{}:{}",
                compose_storage_volume_name(&storage_mount.identity),
                storage_mount.mount_path
            ));
        }
        configure_program_log_shipping(
            &mut program_service,
            &label,
            &compose_component_service_name(&label),
        );

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

    let compose_yaml = serde_yaml::to_string(&compose).map_err(|e| {
        DockerComposeError::Other(format!("failed to serialize docker-compose yaml: {e}"))
    })?;
    let execution_guide =
        build_execution_guide(scenario, &mesh_plan, &config_plan, !storage_plan.is_empty())
            .map_err(|err: ReporterError| DockerComposeError::Other(err.to_string()))?;
    let mut files = BTreeMap::new();
    files.insert(PathBuf::from(GENERATED_COMPOSE_FILENAME), compose_yaml);
    files.insert(
        PathBuf::from(GENERATED_ENV_SAMPLE_FILENAME),
        execution_guide.render_env_sample(true, "docker-compose"),
    );
    files.insert(
        PathBuf::from(GENERATED_README_FILENAME),
        execution_guide.render_compose_readme(),
    );

    Ok(DockerComposeArtifact { files })
}

// ---- helpers ----

fn otelcol_config_content() -> String {
    // We use env vars so users can override upstream and emit stable per-run labels without
    // regenerating compose output.
    format!(
        r#"
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318
  filelog/docker:
    include:
      - {DOCKER_CONTAINER_LOGS_DIR}/*/*-json.log
    start_at: end
    include_file_path: true
    operators:
      - type: json_parser
        parse_from: body
      - type: move
        from: attributes.log
        to: body
      - type: move
        from: attributes.stream
        to: attributes.amber_stream
      - type: json_parser
        if: body matches "^[{{]"
        parse_from: body
      - type: severity_parser
        if: attributes.level != nil
        parse_from: attributes.level
      - type: move
        if: attributes.message != nil
        from: attributes.message
        to: body
      - type: time_parser
        parse_from: attributes.time
        layout_type: gotime
        layout: '2006-01-02T15:04:05.999999999Z07:00'
      - type: remove
        field: attributes.time
        if: attributes.time != nil

processors:
  memory_limiter:
    check_interval: 1s
    limit_mib: 256
    spike_limit_mib: 128
  batch: {{}}
  resource/amber:
    attributes:
      - key: amber.scenario.run_id
        action: upsert
        value: $${{env:{SCENARIO_RUN_ID_ENV}}}
  transform/program_logs:
    error_mode: ignore
    log_statements:
      - context: scope
        statements:
          - set(scope.name, "amber.program")
      - context: log
        statements:
          - set(log.attributes["service.name"], log.attributes["attrs"]["{LOG_LABEL_SERVICE_NAME}"]) where log.attributes["attrs"] != nil and log.attributes["attrs"]["{LOG_LABEL_SERVICE_NAME}"] != nil
          - set(log.attributes["amber.component.moniker"], log.attributes["attrs"]["{LOG_LABEL_MONIKER}"]) where log.attributes["attrs"] != nil and log.attributes["attrs"]["{LOG_LABEL_MONIKER}"] != nil
          - delete_key(log.attributes, "attrs") where log.attributes["attrs"] != nil
          - set(log.severity_number, SEVERITY_NUMBER_ERROR) where log.severity_number == 0 and IsString(log.body) and IsMatch(log.body, "(?i)\\b(error|failed|exception|fatal|panic)\\b")
          - set(log.severity_number, SEVERITY_NUMBER_WARN) where log.severity_number == 0 and IsString(log.body) and IsMatch(log.body, "(?i)\\b(warn|warning)\\b")
          - set(log.severity_number, SEVERITY_NUMBER_WARN) where log.severity_number == 0 and log.attributes["amber_stream"] == "stderr"
          - set(log.severity_number, SEVERITY_NUMBER_INFO) where log.severity_number == 0
          - set(log.severity_text, "Error") where log.severity_text == "" and log.severity_number >= SEVERITY_NUMBER_ERROR
          - set(log.severity_text, "Warning") where log.severity_text == "" and log.severity_number >= SEVERITY_NUMBER_WARN and log.severity_number < SEVERITY_NUMBER_ERROR
          - set(log.severity_text, "Information") where log.severity_text == "" and log.severity_number >= SEVERITY_NUMBER_INFO and log.severity_number < SEVERITY_NUMBER_WARN
  filter/program_logs:
    error_mode: ignore
    logs:
      log_record:
        - log.attributes["service.name"] == nil
        - log.attributes["amber.component.moniker"] == nil
  groupbyattrs/program_log_identity:
    keys:
      - service.name
      - amber.component.moniker

exporters:
  otlphttp/upstream:
    endpoint: $${{env:{OTELCOL_UPSTREAM_ENV}}}
    compression: none
    encoding: proto

service:
  telemetry:
    logs:
      level: warn
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, resource/amber, batch]
      exporters: [otlphttp/upstream]
    logs/otlp:
      receivers: [otlp]
      processors: [memory_limiter, resource/amber, batch]
      exporters: [otlphttp/upstream]
    logs/program:
      receivers: [filelog/docker]
      processors: [memory_limiter, transform/program_logs, filter/program_logs, groupbyattrs/program_log_identity, resource/amber, batch]
      exporters: [otlphttp/upstream]
    metrics:
      receivers: [otlp]
      processors: [memory_limiter, resource/amber, batch]
      exporters: [otlphttp/upstream]
"#
    )
}

fn push_router_observability_env(env_entries: &mut Vec<String>) {
    env_entries.push(format!(
        "{SCENARIO_RUN_ID_ENV}=${{{COMPOSE_PROJECT_NAME_ENV}:-default}}"
    ));
    env_entries.push("OTEL_TRACES_SAMPLER=always_on".to_string());
    env_entries.push("OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf".to_string());
    env_entries.push(format!(
        "OTEL_EXPORTER_OTLP_ENDPOINT={ROUTER_OTLP_ENDPOINT}"
    ));
}

fn push_program_observability_env(
    env_entries: &mut Vec<String>,
    component_moniker: &str,
    scenario_scope: Option<&str>,
) {
    env_entries.push(format!(
        "{SCENARIO_RUN_ID_ENV}=${{{COMPOSE_PROJECT_NAME_ENV}:-default}}"
    ));
    env_entries.push("OTEL_TRACES_SAMPLER=always_on".to_string());
    env_entries.push("OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf".to_string());
    env_entries.push(format!(
        "OTEL_EXPORTER_OTLP_ENDPOINT={ROUTER_OTLP_ENDPOINT}"
    ));
    env_entries.push(format!("AMBER_COMPONENT_MONIKER={component_moniker}"));
    if let Some(scope) = scenario_scope {
        env_entries.push(format!("AMBER_SCENARIO_SCOPE={scope}"));
    }
}

fn push_program_observability_env_map(
    env_entries: &mut BTreeMap<String, String>,
    component_moniker: &str,
    scenario_scope: Option<&str>,
) {
    env_entries.insert(
        SCENARIO_RUN_ID_ENV.to_string(),
        format!("${{{COMPOSE_PROJECT_NAME_ENV}:-default}}"),
    );
    env_entries.insert("OTEL_TRACES_SAMPLER".to_string(), "always_on".to_string());
    env_entries.insert(
        "OTEL_EXPORTER_OTLP_PROTOCOL".to_string(),
        "http/protobuf".to_string(),
    );
    env_entries.insert(
        "OTEL_EXPORTER_OTLP_ENDPOINT".to_string(),
        ROUTER_OTLP_ENDPOINT.to_string(),
    );
    env_entries.insert(
        "AMBER_COMPONENT_MONIKER".to_string(),
        component_moniker.to_string(),
    );
    if let Some(scope) = scenario_scope {
        env_entries.insert("AMBER_SCENARIO_SCOPE".to_string(), scope.to_string());
    }
}

fn compose_component_service_name(component_moniker: &str) -> String {
    format!(
        "amber.${{{COMPOSE_PROJECT_NAME_ENV}:-default}}.{}",
        sanitize_component_moniker(component_moniker)
    )
}

fn compose_storage_volume_name(identity: &StorageIdentity) -> String {
    format!(
        "amber-storage-{}-{}-{}",
        sanitize_component_moniker(identity.owner_moniker.as_str()),
        sanitize_component_moniker(identity.resource.as_str()),
        identity.hash_suffix(),
    )
}

fn sanitize_component_moniker(component_moniker: &str) -> String {
    let sanitized = component_moniker.trim_matches('/').replace('/', ".");
    if sanitized.is_empty() {
        "root".to_string()
    } else {
        sanitized
    }
}

fn configure_program_log_shipping(
    service: &mut Service,
    component_moniker: &str,
    service_name: &str,
) {
    service
        .labels
        .insert(LOG_LABEL_MONIKER.to_string(), component_moniker.to_string());
    service
        .labels
        .insert(LOG_LABEL_SERVICE_NAME.to_string(), service_name.to_string());
    service.logging = Some(ServiceLogging {
        driver: "json-file".to_string(),
        options: BTreeMap::from([("labels".to_string(), LOG_LABEL_LIST.to_string())]),
    });
}

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
        let paths: Vec<String> = scenario
            .component(*component)
            .program
            .as_ref()
            .into_iter()
            .flat_map(|program| program.mounts())
            .filter_map(|mount| match mount {
                ProgramMount::Framework { path, capability } if capability.as_str() == "docker" => {
                    Some(path.clone())
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

fn configure_injected_docker_gateway_service(
    service: &mut Service,
    scenario: &Scenario,
    id: ComponentId,
    names: &ServiceNames,
) -> DcResult<()> {
    let config_json =
        build_docker_gateway_config_json(scenario.component(id).moniker.as_str(), &names.program)?;
    match service.environment.take() {
        Some(Environment::Map(mut env)) => {
            env.insert(DOCKER_GATEWAY_CONFIG_ENV.to_string(), config_json);
            service.environment = Some(Environment::Map(env));
        }
        Some(Environment::List(_)) => {
            return Err(DockerComposeError::Other(
                "internal error: injected docker gateway should not use list-style environment"
                    .to_string(),
            ));
        }
        None => {
            service.environment = Some(Environment::Map(BTreeMap::from([(
                DOCKER_GATEWAY_CONFIG_ENV.to_string(),
                config_json,
            )])));
        }
    }
    service.volumes.push(format!(
        "${{{DOCKER_GATEWAY_HOST_SOCK_ENV}:-{}}}:{DOCKER_GATEWAY_CONTAINER_SOCK}",
        detect_default_host_docker_sock().display()
    ));
    Ok(())
}

fn docker_proxy_ports_by_component(
    scenario: &Scenario,
    route_ports: &LocalRoutePorts,
    proxy_slot_by_component: &HashMap<ComponentId, String>,
) -> DcResult<HashMap<ComponentId, u16>> {
    let mut ports = HashMap::new();
    for (component, slot_name) in proxy_slot_by_component {
        let listen_port = route_ports
            .slot_port(*component, slot_name)
            .ok_or_else(|| {
                DockerComposeError::Other(format!(
                    "internal error: missing local slot port for {}.{}",
                    component_label(scenario, *component),
                    slot_name
                ))
            })?;
        ports.insert(*component, listen_port);
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

fn build_docker_gateway_config_json(
    caller_component: &str,
    caller_compose_service: &str,
) -> DcResult<String> {
    let callers = vec![DockerGatewayCallerConfig {
        host: "127.0.0.1".to_string(),
        port: None,
        component: caller_component.to_string(),
        compose_service: caller_compose_service.to_string(),
    }];

    let config = DockerGatewayConfig {
        listen: format!("0.0.0.0:{FRAMEWORK_DOCKER_GATEWAY_PORT}"),
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
    root_inputs: &BTreeMap<String, RootInputDescriptor>,
    allowed_leaf_paths: &BTreeSet<String>,
) -> Result<Vec<String>, DockerComposeError> {
    let mut entries = Vec::new();
    for (path, input) in root_inputs {
        if !allowed_leaf_paths.contains(path) {
            continue;
        }
        let var = &input.env_var;
        if input.required {
            entries.push(format!("{var}=${{{var}?missing config.{path}}}"));
        } else {
            entries.push(var.clone());
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
                        if let Some(default) = leaf.default.as_ref() {
                            let default =
                                rc::stringify_for_interpolation(default).map_err(|err| {
                                    format!(
                                        "runtime program.image path config.{path} has a default \
                                         that cannot be interpolated into an image string: {err}"
                                    )
                                })?;
                            rendered.push_str(&format!(
                                "${{{env_var}:-{}}}",
                                escape_compose_interpolation(&default)
                            ));
                        } else if leaf.runtime_required() {
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

fn compose_control_socket_volume_expr() -> String {
    format!(
        "${{{}:-default}}_{}",
        COMPOSE_PROJECT_NAME_ENV, ROUTER_CONTROL_SOCKET_VOLUME_NAME
    )
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

fn escape_compose_interpolation<'a>(line: &'a str) -> Cow<'a, str> {
    if line.contains('$') {
        Cow::Owned(line.replace('$', "$$"))
    } else {
        Cow::Borrowed(line)
    }
}

#[cfg(test)]
mod tests;
