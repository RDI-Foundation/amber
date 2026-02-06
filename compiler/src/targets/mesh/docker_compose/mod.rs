use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
};

use amber_config as rc;
use amber_scenario::{ComponentId, Scenario};
use serde::{Deserialize, Serialize};

use crate::{
    CompileOutput,
    reporter::{Reporter, ReporterError},
    targets::mesh::{
        addressing::{Addressing, build_address_plan},
        config::{ProgramPlan, encode_helper_payload, encode_schema_b64},
        internal_images::resolve_internal_images,
        mesh_config::{MeshAddressing, RouterPorts, build_mesh_config_plan},
        plan::{MeshError, MeshOptions, ResolvedBinding, ResolvedExternalBinding, component_label},
        ports::{allocate_mesh_ports, allocate_slot_ports},
        proxy_metadata::{ProxyMetadata, RouterMetadata, build_proxy_metadata},
    },
};

const MESH_NETWORK_NAME: &str = "amber_mesh";

const ROUTER_SERVICE_NAME: &str = "amber-router";
const HELPER_VOLUME_NAME: &str = "amber-helper-bin";
const HELPER_INIT_SERVICE: &str = "amber-init";
const HELPER_BIN_DIR: &str = "/amber/bin";
const HELPER_BIN_PATH: &str = "/amber/bin/amber-helper";

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
struct Service {
    image: String,
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
    .map_err(|e| DockerComposeError::Other(e.to_string()))?;
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
    let has_external_slots = !mesh_plan.external_bindings.is_empty();
    let router_config_b64 = mesh_config_plan
        .router_config
        .as_ref()
        .map(amber_mesh::encode_config_b64)
        .transpose()
        .map_err(|err| DockerComposeError::Other(err.to_string()))?;
    let router_metadata = router_config_b64.as_ref().map(|config_b64| RouterMetadata {
        config_b64: config_b64.clone(),
        mesh_port: router_mesh_port,
        control_port: router_ports.as_ref().expect("router ports missing").control,
    });
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

    // Compose YAML
    // ---- runtime config / helper decision ----
    let config_plan = crate::targets::mesh::config::build_config_plan(
        s,
        program_components,
        &address_plan.slot_values_by_component,
        &address_plan.binding_values_by_component,
    )
    .map_err(|e| DockerComposeError::Other(e.to_string()))?;

    // Root schema payloads + AMBER_CONFIG_* env list are only needed if at least one service uses the helper.
    let mut root_schema_b64: Option<String> = None;
    let mut root_env_entries: Vec<String> = Vec::new();

    if config_plan.uses_helper {
        let root_schema = config_plan
            .root_schema
            .as_ref()
            .expect("helper usage implies root schema");
        root_schema_b64 = Some(
            encode_schema_b64("root config definition", root_schema)
                .map_err(|e| DockerComposeError::Other(e.to_string()))?,
        );

        for leaf in &config_plan.root_leaves {
            let var = rc::env_var_for_path(&leaf.path)
                .map_err(|e| format!("failed to map config path {} to env var: {e}", leaf.path))?;
            if leaf.required {
                root_env_entries.push(format!("{var}=${{{var}?missing config.{}}}", leaf.path));
            } else {
                root_env_entries.push(var);
            }
        }
    }

    let program_plans = &config_plan.program_plans;
    let any_helper = config_plan.uses_helper;

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

    if needs_router {
        let router_config_b64 = router_config_b64
            .as_ref()
            .expect("router config should exist");
        let mut env_entries = mesh_config_plan.router_env_passthrough.clone();
        env_entries.push(format!("AMBER_ROUTER_CONFIG_B64={router_config_b64}"));
        let mut router_service = Service::new(images.router.clone());
        router_service.environment = Some(Environment::List(env_entries));
        if has_external_slots {
            router_service
                .extra_hosts
                .push("host.docker.internal:host-gateway".to_string());
        }
        router_service
            .networks
            .insert(MESH_NETWORK_NAME.to_string(), EmptyMap::default());
        router_service
            .ports
            .push(format!("127.0.0.1:{router_mesh_port}:{router_mesh_port}"));
        if let Some(ports) = router_ports {
            router_service
                .ports
                .push(format!("127.0.0.1:{}:{}", ports.control, ports.control));
        }

        if !exports_by_name.is_empty() {
            let labels_json = serde_json::to_string(&exports_by_name)
                .map_err(|err| format!("failed to serialize router export labels: {err}"))?;
            router_service
                .labels
                .insert("amber.exports".to_string(), labels_json);
        }

        compose
            .services
            .insert(ROUTER_SERVICE_NAME.to_string(), router_service);
    }

    // Emit services in stable (component id) order, sidecar then program.
    for id in program_components {
        let c = s.component(*id);
        let svc = names.get(id).unwrap();

        let sidecar_config = mesh_config_plan
            .component_configs
            .get(id)
            .expect("sidecar config missing");
        let sidecar_config_b64 = amber_mesh::encode_config_b64(sidecar_config)
            .map_err(|err| DockerComposeError::Other(err.to_string()))?;
        let mut sidecar_service = Service::new(images.router.clone());
        sidecar_service.environment = Some(Environment::List(vec![format!(
            "AMBER_ROUTER_CONFIG_B64={sidecar_config_b64}"
        )]));
        sidecar_service
            .networks
            .insert(MESH_NETWORK_NAME.to_string(), EmptyMap::default());
        compose
            .services
            .insert(svc.sidecar.clone(), sidecar_service);

        let program = c.program.as_ref().unwrap();
        let mut program_service = Service::new(program.image.as_str());
        program_service.network_mode = Some(format!("service:{}", svc.sidecar));

        // depends_on: own sidecar + strong deps provider programs (+ amber-init for helper-backed services)
        let program_plan = program_plans.get(id).expect("program plan computed");
        let mut deps: Vec<(String, &'static str)> = Vec::new();
        if any_helper && matches!(program_plan, ProgramPlan::Helper { .. }) {
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
        program_service.depends_on = build_depends_on(any_helper, deps);

        match program_plan {
            ProgramPlan::Direct { entrypoint, env } => {
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
            ProgramPlan::Helper {
                template_spec,
                component_template,
                component_schema,
            } => {
                let label = component_label(s, *id);
                let payload = encode_helper_payload(
                    &label,
                    template_spec,
                    component_template,
                    component_schema,
                )
                .map_err(|e| DockerComposeError::Other(e.to_string()))?;

                // Mount helper binary and run it as PID1; it execs the program entrypoint.
                program_service
                    .volumes
                    .push(format!("{HELPER_VOLUME_NAME}:{HELPER_BIN_DIR}:ro"));
                program_service.entrypoint =
                    Some(vec![HELPER_BIN_PATH.to_string(), "run".to_string()]);

                let mut env_entries = root_env_entries.clone();
                let root_schema_b64 = root_schema_b64.as_ref().expect("helper enabled");
                env_entries.push(format!("AMBER_ROOT_CONFIG_SCHEMA_B64={root_schema_b64}"));
                env_entries.push(format!(
                    "AMBER_COMPONENT_CONFIG_SCHEMA_B64={}",
                    payload.component_schema_b64
                ));
                env_entries.push(format!(
                    "AMBER_COMPONENT_CONFIG_TEMPLATE_B64={}",
                    payload.component_cfg_template_b64
                ));
                env_entries.push(format!(
                    "AMBER_TEMPLATE_SPEC_B64={}",
                    payload.template_spec_b64
                ));
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

fn build_depends_on(any_helper: bool, deps: Vec<(String, &'static str)>) -> Option<DependsOn> {
    if deps.is_empty() {
        return None;
    }
    if any_helper {
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

fn service_base_name(id: ComponentId, local_name: &str) -> String {
    // Ensure injective via numeric prefix; keep human-readable suffix.
    let slug = sanitize_service_suffix(local_name);
    format!("c{}-{}", id.0, slug)
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
