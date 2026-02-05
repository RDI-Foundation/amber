use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt::Write as _,
};

use amber_config as rc;
use amber_scenario::{ComponentId, Scenario};
use miette::LabeledSpan;
use serde::{Deserialize, Serialize};

use crate::{
    CompileOutput,
    reporter::{Reporter, ReporterError},
    targets::mesh::{
        LOCAL_NETWORK_CIDRS,
        addressing::{Addressing, RouterPortBases, WorkloadId, build_address_plan},
        config::{ProgramPlan, encode_helper_payload, encode_schema_b64},
        internal_images::resolve_internal_images,
        plan::{
            MeshOptions, ResolvedBinding, ResolvedExport, ResolvedExternalBinding, component_label,
        },
    },
};

const MESH_NETWORK_NAME: &str = "amber_mesh";

const ROUTER_SERVICE_NAME: &str = "amber-router";
const HELPER_VOLUME_NAME: &str = "amber-helper-bin";
const HELPER_INIT_SERVICE: &str = "amber-init";
const HELPER_BIN_DIR: &str = "/amber/bin";
const HELPER_BIN_PATH: &str = "/amber/bin/amber-helper";

const LOCAL_PROXY_PORT_BASE: u16 = 20000;
const ROUTER_EXTERNAL_PORT_BASE: u16 = 21000;
const ROUTER_EXPORT_PORT_BASE: u16 = 22000;
const EXPORT_PORT_BASE: u16 = 18000;
const EXPORT_HOST: &str = "127.0.0.1";

#[derive(Clone, Copy, Debug, Default)]
pub struct DockerComposeReporter;

impl Reporter for DockerComposeReporter {
    type Artifact = String;

    fn emit(&self, scenario: &Scenario) -> Result<Self::Artifact, ReporterError> {
        render_docker_compose(scenario)
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
    x_amber: Option<AmberExtension>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct AmberExtension {
    exports: BTreeMap<String, ExportMetadata>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct EmptyMap {}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct NetworkConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    aliases: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct Network {
    driver: String,
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        rename = "driver_opts"
    )]
    driver_opts: BTreeMap<String, String>,
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
    networks: BTreeMap<String, NetworkConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    entrypoint: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    environment: Option<Environment>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    ports: Vec<String>,
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

#[derive(Clone, Debug)]
struct SlotProxy {
    local_port: u16,
    remote_host: String,
    remote_port: u16,
}

#[derive(Clone, Debug)]
struct ComposeAddressExtra {
    slot_proxies_by_component: HashMap<ComponentId, Vec<SlotProxy>>,
}

struct ComposeAddressing<'a> {
    scenario: &'a Scenario,
    names: &'a HashMap<ComponentId, ServiceNames>,
    router_names: ServiceNames,
    slot_ports_by_component: HashMap<ComponentId, BTreeMap<String, u16>>,
    slot_proxies_by_component: HashMap<ComponentId, Vec<SlotProxy>>,
    port_owner: HashMap<(ComponentId, u16), (String, String)>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ExportMetadata {
    published_host: String,
    published_port: u16,
    target_port: u16,
    component: String,
    provide: String,
    endpoint: String,
}

#[derive(Debug)]
struct PortConflict {
    component: ComponentId,
    port: u16,
    first_provide: String,
    first_endpoint: String,
    provide: String,
    endpoint: String,
}

#[derive(Debug)]
enum DockerComposeError {
    Other(String),
    PortConflict(Box<PortConflict>),
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
    fn into_reporter_error(self, scenario: &Scenario) -> ReporterError {
        match self {
            DockerComposeError::Other(message) => ReporterError::new(message),
            DockerComposeError::PortConflict(conflict) => {
                let PortConflict {
                    component,
                    port,
                    first_provide,
                    first_endpoint,
                    provide,
                    endpoint,
                } = *conflict;
                let component_moniker = scenario.component(component).moniker.as_str();
                let message = format!(
                    "docker-compose output cannot enforce separate capabilities for provides \
                     `{first_provide}` and `{provide}` in component `{component_moniker}`: both \
                     route to port {port} via endpoints `{first_endpoint}` and `{endpoint}`"
                );
                let help = "Expose each capability on its own port, or add an explicit L7 proxy \
                            component that maps each capability to a separate port.";
                ReporterError::new(message).with_help(help)
            }
        }
    }

    fn into_reporter_error_with_spans(self, output: &CompileOutput) -> ReporterError {
        match self {
            DockerComposeError::Other(message) => ReporterError::new(message),
            DockerComposeError::PortConflict(conflict) => port_conflict_report(output, &conflict),
        }
    }
}

fn port_conflict_report(output: &CompileOutput, conflict: &PortConflict) -> ReporterError {
    let PortConflict {
        component,
        port,
        first_provide,
        first_endpoint,
        provide,
        endpoint,
    } = conflict;
    let component_moniker = output.scenario.component(*component).moniker.as_str();
    let message = format!(
        "docker-compose output cannot enforce separate capabilities for provides \
         `{first_provide}` and `{provide}` in component `{component_moniker}`: both route to port \
         {port} via endpoints `{first_endpoint}` and `{endpoint}`"
    );
    let help = "Expose each capability on its own port, or add an explicit L7 proxy component \
                that maps each capability to a separate port.";

    let prov = output.provenance.for_component(*component);
    let Some((src, spans)) = output.store.diagnostic_source(&prov.resolved_url) else {
        return ReporterError::new(message).with_help(help);
    };

    let mut labels = Vec::new();
    let mut has_primary = false;

    let provide_span = |name: &str| {
        spans
            .provides
            .get(name)
            .map(|s| s.capability.name)
            .or_else(|| spans.provides.get(name).map(|s| s.capability.whole))
    };

    let endpoint_span = |name: &str| {
        spans
            .program
            .as_ref()?
            .endpoints
            .iter()
            .find(|endpoint| endpoint.name.as_ref() == name)
    };

    if let Some(endpoint_span) = endpoint_span(first_endpoint) {
        let span = endpoint_span.port_span.unwrap_or(endpoint_span.whole);
        labels.push(LabeledSpan::new_primary_with_span(
            Some(format!("port used by provide `{first_provide}`")),
            span,
        ));
        has_primary = true;
    }
    if let Some(endpoint_span) = endpoint_span(endpoint) {
        let span = endpoint_span.port_span.unwrap_or(endpoint_span.whole);
        let label = Some(format!("port used by provide `{provide}`"));
        if has_primary {
            labels.push(LabeledSpan::new_with_span(label, span));
        } else {
            labels.push(LabeledSpan::new_primary_with_span(label, span));
            has_primary = true;
        }
    }

    if !has_primary {
        if let Some(span) = provide_span(first_provide) {
            labels.push(LabeledSpan::new_primary_with_span(
                Some(format!("provide `{first_provide}`")),
                span,
            ));
            has_primary = true;
        }
        if let Some(span) = provide_span(provide) {
            let label = Some(format!("provide `{provide}`"));
            if has_primary {
                labels.push(LabeledSpan::new_with_span(label, span));
            } else {
                labels.push(LabeledSpan::new_primary_with_span(label, span));
            }
        }
    }

    ReporterError::new(message)
        .with_help(help)
        .with_source_code(src)
        .with_labels(labels)
}

type DcResult<T> = Result<T, DockerComposeError>;

pub fn validate_docker_compose(output: &CompileOutput) -> Result<(), ReporterError> {
    let s = &output.scenario;

    let mesh_plan = crate::targets::mesh::plan::build_mesh_plan(
        s,
        MeshOptions {
            backend_label: "docker-compose reporter",
        },
    )
    .map_err(|e| ReporterError::new(e.to_string()))?;

    let program_components = mesh_plan.program_components.as_slice();

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
    let router_names = ServiceNames {
        program: ROUTER_SERVICE_NAME.to_string(),
        sidecar: format!("{ROUTER_SERVICE_NAME}-net"),
    };

    let root_slots = &s.component(s.root).slots;
    let addressing = ComposeAddressing::new(s, program_components, &names, router_names)
        .map_err(|err| err.into_reporter_error_with_spans(output))?;
    build_address_plan(
        &mesh_plan,
        root_slots,
        RouterPortBases {
            external: ROUTER_EXTERNAL_PORT_BASE,
            export: ROUTER_EXPORT_PORT_BASE,
        },
        addressing,
    )
    .map_err(|err| err.into_reporter_error_with_spans(output))?;

    Ok(())
}

impl<'a> ComposeAddressing<'a> {
    fn new(
        scenario: &'a Scenario,
        program_components: &'a [ComponentId],
        names: &'a HashMap<ComponentId, ServiceNames>,
        router_names: ServiceNames,
    ) -> Result<Self, DockerComposeError> {
        let slot_ports_by_component = allocate_local_proxy_ports(scenario, program_components)?;

        Ok(Self {
            scenario,
            names,
            router_names,
            slot_ports_by_component,
            slot_proxies_by_component: HashMap::new(),
            port_owner: HashMap::new(),
        })
    }

    fn sidecar_host(&self, component: ComponentId) -> Result<String, DockerComposeError> {
        self.names
            .get(&component)
            .ok_or_else(|| {
                format!(
                    "internal error: missing sidecar name for component {}",
                    component_label(self.scenario, component)
                )
            })
            .map(|svc| svc.sidecar.clone())
            .map_err(DockerComposeError::Other)
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

    fn record_proxy(
        &mut self,
        consumer: ComponentId,
        local_port: u16,
        remote_host: String,
        remote_port: u16,
    ) {
        self.slot_proxies_by_component
            .entry(consumer)
            .or_default()
            .push(SlotProxy {
                local_port,
                remote_host,
                remote_port,
            });
    }
}

impl Addressing for ComposeAddressing<'_> {
    type Extra = ComposeAddressExtra;
    type Error = DockerComposeError;

    fn resolve_binding_url(&mut self, binding: &ResolvedBinding) -> Result<String, Self::Error> {
        let endpoint = &binding.endpoint;

        enforce_single_endpoint_per_port(
            &mut self.port_owner,
            binding.provider,
            endpoint.port,
            &binding.provide,
            &endpoint.name,
        )?;

        let local_port = self.local_proxy_port(binding.consumer, &binding.slot)?;
        let remote_host = if binding.provider == binding.consumer {
            "127.0.0.1".to_string()
        } else {
            self.sidecar_host(binding.provider)?
        };

        self.record_proxy(binding.consumer, local_port, remote_host, endpoint.port);

        Ok(format!("http://127.0.0.1:{local_port}"))
    }

    fn resolve_external_binding_url(
        &mut self,
        binding: &ResolvedExternalBinding,
        router_port: u16,
    ) -> Result<String, Self::Error> {
        let local_port = self.local_proxy_port(binding.consumer, &binding.slot)?;
        let remote_host = self.router_names.sidecar.clone();

        self.record_proxy(binding.consumer, local_port, remote_host, router_port);

        Ok(format!("http://127.0.0.1:{local_port}"))
    }

    fn resolve_export_target_url(
        &mut self,
        export: &ResolvedExport,
    ) -> Result<String, Self::Error> {
        let endpoint = &export.endpoint;
        enforce_single_endpoint_per_port(
            &mut self.port_owner,
            export.provider,
            endpoint.port,
            &export.provide,
            &endpoint.name,
        )?;

        let provider_host = self.sidecar_host(export.provider)?;
        Ok(format!("http://{provider_host}:{}", endpoint.port))
    }

    fn finalize(self) -> Self::Extra {
        ComposeAddressExtra {
            slot_proxies_by_component: self.slot_proxies_by_component,
        }
    }
}

fn render_docker_compose(scenario: &Scenario) -> Result<String, ReporterError> {
    render_docker_compose_inner(scenario).map_err(|err| err.into_reporter_error(scenario))
}

fn render_docker_compose_inner(s: &Scenario) -> DcResult<String> {
    let mesh_plan = crate::targets::mesh::plan::build_mesh_plan(
        s,
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
    let router_names = ServiceNames {
        program: ROUTER_SERVICE_NAME.to_string(),
        sidecar: format!("{ROUTER_SERVICE_NAME}-net"),
    };

    let root_slots = &s.component(s.root).slots;

    let addressing = ComposeAddressing::new(s, program_components, &names, router_names.clone())?;
    let address_plan = build_address_plan(
        &mesh_plan,
        root_slots,
        RouterPortBases {
            external: ROUTER_EXTERNAL_PORT_BASE,
            export: ROUTER_EXPORT_PORT_BASE,
        },
        addressing,
    )?;
    let ComposeAddressExtra {
        slot_proxies_by_component,
    } = address_plan.extra;
    let needs_router = address_plan.router.needs_router;

    let map_allowed_hosts =
        |by_port: Option<&BTreeMap<u16, BTreeSet<WorkloadId>>>|
         -> DcResult<BTreeMap<u16, BTreeSet<String>>> {
        let mut out: BTreeMap<u16, BTreeSet<String>> = BTreeMap::new();
        let Some(by_port) = by_port else {
            return Ok(out);
        };
        for (port, consumers) in by_port {
            let mut hosts: BTreeSet<String> = BTreeSet::new();
            for consumer in consumers {
                let host = match consumer {
                    WorkloadId::Component(id) => names
                        .get(id)
                        .ok_or_else(|| {
                            format!(
                                "internal error: missing sidecar name for consumer {}",
                                component_label(s, *id)
                            )
                        })?
                        .sidecar
                        .clone(),
                    WorkloadId::Router => router_names.sidecar.clone(),
                };
                hosts.insert(host);
            }
            if !hosts.is_empty() {
                out.insert(*port, hosts);
            }
        }
        Ok(out)
    };

    // Scenario exports => publish to host loopback with stable host ports (via router).
    let mut exports_by_name: BTreeMap<String, ExportMetadata> = BTreeMap::new();
    {
        let mut next_host_port = EXPORT_PORT_BASE;
        for ex in &mesh_plan.exports {
            let provider = ex.provider;
            let endpoint = &ex.endpoint;

            let published = next_host_port;
            next_host_port = next_host_port.checked_add(1).ok_or_else(|| {
                "ran out of host ports while allocating scenario exports".to_string()
            })?;

            let metadata = ExportMetadata {
                published_host: EXPORT_HOST.to_string(),
                published_port: published,
                target_port: endpoint.port,
                component: component_label(s, provider),
                provide: ex.provide.clone(),
                endpoint: endpoint.name.clone(),
            };

            exports_by_name.insert(ex.name.clone(), metadata);
        }
    }

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
        let router_inbound_allow = map_allowed_hosts(address_plan.allow.for_router())?;
        let router_inbound: Vec<(u16, &BTreeSet<String>)> = router_inbound_allow
            .iter()
            .map(|(port, srcs)| (*port, srcs))
            .collect();
        let router_script = build_sidecar_script(
            s.root,
            router_inbound,
            if address_plan.router.export_ports.is_empty() {
                None
            } else {
                Some(&address_plan.router.export_ports)
            },
            None,
            false,
        );
        let router_script = escape_compose_interpolation(&router_script).into_owned();

        let mut router_sidecar =
            sidecar_service(&router_names.sidecar, &images.sidecar, router_script);
        if !exports_by_name.is_empty() {
            for (export_name, meta) in &exports_by_name {
                let router_port = address_plan
                    .router
                    .export_ports_by_name
                    .get(export_name)
                    .expect("router export port missing");
                let spec = format!(
                    "{}:{}:{}",
                    meta.published_host, meta.published_port, router_port
                );
                router_sidecar.ports.push(spec);
            }

            let labels_json = serde_json::to_string(&exports_by_name)
                .map_err(|err| format!("failed to serialize router export labels: {err}"))?;
            router_sidecar
                .labels
                .insert("amber.exports".to_string(), labels_json);
        }

        compose
            .services
            .insert(router_names.sidecar.clone(), router_sidecar);

        let mut router_program = Service::new(images.router.clone());
        router_program.network_mode = Some(format!("service:{}", router_names.sidecar));

        let mut env_entries = address_plan.router.router_env_passthrough.clone();
        let router_config_b64 = address_plan
            .router
            .router_config_b64
            .as_ref()
            .expect("router config should be computed");
        env_entries.push(format!("AMBER_ROUTER_CONFIG_B64={router_config_b64}"));
        router_program.environment = Some(Environment::List(env_entries));

        let mut depends = BTreeMap::new();
        depends.insert(
            router_names.sidecar.clone(),
            DependsOnCondition {
                condition: "service_started".to_string(),
            },
        );
        router_program.depends_on = Some(DependsOn::Conditions(depends));

        compose
            .services
            .insert(router_names.program.clone(), router_program);
    }

    // Emit services in stable (component id) order, sidecar then program.
    for id in program_components {
        let c = s.component(*id);
        let svc = names.get(id).unwrap();

        let inbound_allow = map_allowed_hosts(address_plan.allow.for_component(*id))?;
        let script = build_sidecar_script(
            *id,
            inbound_allow
                .iter()
                .map(|(port, srcs)| (*port, srcs))
                .collect(),
            None,
            slot_proxies_by_component.get(id),
            true,
        );
        let script = escape_compose_interpolation(&script).into_owned();
        compose.services.insert(
            svc.sidecar.clone(),
            sidecar_service(&svc.sidecar, &images.sidecar, script),
        );

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
            driver_opts: BTreeMap::from([(
                "com.docker.network.bridge.enable_ip_masquerade".to_string(),
                "true".to_string(),
            )]),
        },
    );

    if !exports_by_name.is_empty() {
        compose.x_amber = Some(AmberExtension {
            exports: exports_by_name.clone(),
        });
    }

    serde_yaml::to_string(&compose).map_err(|e| {
        DockerComposeError::Other(format!("failed to serialize docker-compose yaml: {e}"))
    })
}

// ---- helpers ----

fn sidecar_service(name: &str, image: &str, script: String) -> Service {
    let mut service = Service::new(image);
    service.cap_add = vec!["NET_ADMIN".to_string()];
    service.cap_drop = vec!["ALL".to_string()];
    service.security_opt = vec!["no-new-privileges:true".to_string()];
    service.networks.insert(
        MESH_NETWORK_NAME.to_string(),
        NetworkConfig {
            aliases: vec![name.to_string()],
        },
    );
    service.command = Some(vec!["/bin/sh".to_string(), "-lc".to_string(), script]);
    service
}

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

fn enforce_single_endpoint_per_port(
    owner: &mut HashMap<(ComponentId, u16), (String, String)>,
    component: ComponentId,
    port: u16,
    provide_name: &str,
    endpoint_name: &str,
) -> Result<(), DockerComposeError> {
    match owner.get(&(component, port)) {
        None => {
            owner.insert(
                (component, port),
                (provide_name.to_string(), endpoint_name.to_string()),
            );
            Ok(())
        }
        Some((_first_provide, first_endpoint)) if *first_endpoint == endpoint_name => Ok(()),
        Some((first_provide, first_endpoint)) => {
            Err(DockerComposeError::PortConflict(Box::new(PortConflict {
                component,
                port,
                first_provide: first_provide.clone(),
                first_endpoint: first_endpoint.clone(),
                provide: provide_name.to_string(),
                endpoint: endpoint_name.to_string(),
            })))
        }
    }
}

fn allocate_local_proxy_ports(
    s: &Scenario,
    program_components: &[ComponentId],
) -> Result<HashMap<ComponentId, BTreeMap<String, u16>>, String> {
    let mut out: HashMap<ComponentId, BTreeMap<String, u16>> = HashMap::new();

    for id in program_components {
        let c = s.component(*id);
        let program = c.program.as_ref().unwrap();

        // Reserved: any ports the program listens on itself.
        let mut reserved: HashSet<u16> = HashSet::new();
        if let Some(net) = program.network.as_ref() {
            for ep in &net.endpoints {
                reserved.insert(ep.port);
            }
        }

        let mut slot_ports: BTreeMap<String, u16> = BTreeMap::new();
        let mut next = LOCAL_PROXY_PORT_BASE;

        // Stable ordering by slot name.
        for slot_name in c.slots.keys() {
            while reserved.contains(&next) || slot_ports.values().any(|p| *p == next) {
                next = next.checked_add(1).ok_or_else(|| {
                    format!(
                        "ran out of local proxy ports allocating for {}",
                        component_label(s, *id)
                    )
                })?;
            }
            slot_ports.insert(slot_name.clone(), next);
            next = next.checked_add(1).ok_or_else(|| {
                format!(
                    "ran out of local proxy ports allocating for {}",
                    component_label(s, *id)
                )
            })?;
        }

        out.insert(*id, slot_ports);
    }

    Ok(out)
}

// NOTE: template interpolation is now handled structurally via `amber_manifest::InterpolatedString`
// parts and the runtime helper payload IR. The old string re-parser has been removed.

fn build_sidecar_script(
    _component: ComponentId,
    inbound: Vec<(u16, &BTreeSet<String>)>,
    exported_ports: Option<&BTreeSet<u16>>,
    proxies: Option<&Vec<SlotProxy>>,
    block_local_egress: bool,
) -> String {
    let mut script = String::new();

    let mut egress_targets: Vec<(String, u16)> = Vec::new();
    if block_local_egress && let Some(ps) = proxies {
        let mut seen: BTreeSet<(String, u16)> = BTreeSet::new();
        for p in ps {
            seen.insert((p.remote_host.clone(), p.remote_port));
        }
        egress_targets.extend(seen);
    }

    // Minimal, explicit, deterministic.
    writeln!(&mut script, "set -eu").unwrap();

    // Firewall baseline
    writeln!(&mut script, "iptables -w -F").unwrap();
    writeln!(&mut script, "iptables -w -X").unwrap();
    writeln!(&mut script, "iptables -w -P INPUT DROP").unwrap();
    writeln!(&mut script, "iptables -w -P FORWARD DROP").unwrap();
    writeln!(&mut script, "iptables -w -P OUTPUT ACCEPT").unwrap();
    writeln!(&mut script, "iptables -w -A INPUT -i lo -j ACCEPT").unwrap();
    writeln!(
        &mut script,
        "iptables -w -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    )
    .unwrap();
    if block_local_egress {
        writeln!(&mut script, "iptables -w -A OUTPUT -o lo -j ACCEPT").unwrap();
        writeln!(
            &mut script,
            "iptables -w -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
        )
        .unwrap();
        writeln!(
            &mut script,
            "for ns in $(awk '/^nameserver/{{print $2}}' /etc/resolv.conf | awk '$1 ~ \
             /^[0-9]+(\\.[0-9]+){{3}}$/ {{print $1}}'); do"
        )
        .unwrap();
        writeln!(
            &mut script,
            "  iptables -w -A OUTPUT -p udp -m udp --dport 53 -d \"$ns\" -j ACCEPT"
        )
        .unwrap();
        writeln!(
            &mut script,
            "  iptables -w -A OUTPUT -p tcp -m tcp --dport 53 -d \"$ns\" -j ACCEPT"
        )
        .unwrap();
        writeln!(&mut script, "done").unwrap();
        writeln!(&mut script, "iptables -w -N AMBER-ALLOW-OUT").unwrap();
        writeln!(&mut script, "iptables -w -A OUTPUT -j AMBER-ALLOW-OUT").unwrap();
        for cidr in LOCAL_NETWORK_CIDRS {
            writeln!(
                &mut script,
                "iptables -w -A OUTPUT -d {cidr} -p tcp -j REJECT --reject-with tcp-reset"
            )
            .unwrap();
            writeln!(&mut script, "iptables -w -A OUTPUT -d {cidr} -j REJECT").unwrap();
        }
    }
    writeln!(&mut script, "iptables -w -N AMBER-ALLOW").unwrap();
    writeln!(&mut script, "iptables -w -A INPUT -j AMBER-ALLOW").unwrap();

    writeln!(&mut script, "resolve_ipv4() {{").unwrap();
    writeln!(
        &mut script,
        "  getent hosts \"$1\" | awk '$1 ~ /^[0-9]+(\\.[0-9]+){{3}}$/ {{print $1}}' || true"
    )
    .unwrap();
    writeln!(&mut script, "}}").unwrap();
    writeln!(&mut script, "add_rule() {{").unwrap();
    writeln!(&mut script, "  if [ -n \"$1\" ]; then").unwrap();
    writeln!(
        &mut script,
        "    printf '%s\\n' \"$1\" >> \"$desired_rules\""
    )
    .unwrap();
    writeln!(&mut script, "  fi").unwrap();
    writeln!(&mut script, "}}").unwrap();
    if block_local_egress {
        writeln!(&mut script, "add_out_rule() {{").unwrap();
        writeln!(&mut script, "  if [ -n \"$1\" ]; then").unwrap();
        writeln!(&mut script, "    printf '%s\\n' \"$1\" >> \"$desired_out\"").unwrap();
        writeln!(&mut script, "  fi").unwrap();
        writeln!(&mut script, "}}").unwrap();
    }
    writeln!(&mut script, "refresh_allowlist() {{").unwrap();
    writeln!(&mut script, "  set +e").unwrap();
    writeln!(&mut script, "  desired_rules=\"/tmp/amber-allowlist\"").unwrap();
    writeln!(&mut script, "  : > \"$desired_rules\"").unwrap();
    if block_local_egress {
        writeln!(&mut script, "  desired_out=\"/tmp/amber-allowlist-out\"").unwrap();
        writeln!(&mut script, "  : > \"$desired_out\"").unwrap();
    }
    writeln!(
        &mut script,
        "  gateway=\"$(ip -4 route show default | awk 'NR==1 {{print $3}}')\""
    )
    .unwrap();

    // Allow inbound from bound consumers (resolved via DNS).
    let mut inbound_sorted = inbound;
    inbound_sorted.sort_by_key(|(port, _)| *port);
    for (port, srcs) in inbound_sorted {
        for src in srcs {
            writeln!(&mut script, "  for ip in $(resolve_ipv4 \"{src}\"); do").unwrap();
            writeln!(
                &mut script,
                "    add_rule \"-s $ip/32 -p tcp -m tcp --dport {port} -j ACCEPT\""
            )
            .unwrap();
            writeln!(&mut script, "  done").unwrap();
        }
    }

    // Allow inbound from host (exports): loopback + docker gateway.
    if let Some(ports) = exported_ports {
        for port in ports {
            writeln!(
                &mut script,
                "  add_rule \"-s {EXPORT_HOST}/32 -p tcp -m tcp --dport {port} -j ACCEPT\""
            )
            .unwrap();
            writeln!(&mut script, "  if [ -n \"$gateway\" ]; then").unwrap();
            writeln!(
                &mut script,
                "    add_rule \"-s $gateway/32 -p tcp -m tcp --dport {port} -j ACCEPT\""
            )
            .unwrap();
            writeln!(&mut script, "  fi").unwrap();
        }
    }
    if block_local_egress {
        for (host, port) in &egress_targets {
            writeln!(&mut script, "  for ip in $(resolve_ipv4 \"{host}\"); do").unwrap();
            writeln!(
                &mut script,
                "    add_out_rule \"-d $ip/32 -p tcp -m tcp --dport {port} -j ACCEPT\""
            )
            .unwrap();
            writeln!(&mut script, "  done").unwrap();
        }
        writeln!(&mut script, "  if [ -s \"$desired_out\" ]; then").unwrap();
        writeln!(&mut script, "    iptables -w -F AMBER-ALLOW-OUT").unwrap();
        writeln!(&mut script, "    while read -r rule; do").unwrap();
        writeln!(&mut script, "      [ -z \"$rule\" ] && continue").unwrap();
        writeln!(&mut script, "      iptables -w -A AMBER-ALLOW-OUT $rule").unwrap();
        writeln!(&mut script, "    done < \"$desired_out\"").unwrap();
        writeln!(&mut script, "  fi").unwrap();
    }
    writeln!(&mut script, "  if [ -s \"$desired_rules\" ]; then").unwrap();
    writeln!(&mut script, "    iptables -w -F AMBER-ALLOW").unwrap();
    writeln!(&mut script, "    while read -r rule; do").unwrap();
    writeln!(&mut script, "      [ -z \"$rule\" ] && continue").unwrap();
    writeln!(&mut script, "      iptables -w -A AMBER-ALLOW $rule").unwrap();
    writeln!(&mut script, "    done < \"$desired_rules\"").unwrap();
    writeln!(&mut script, "  fi").unwrap();
    writeln!(&mut script, "  set -e").unwrap();
    writeln!(&mut script, "  return 0").unwrap();
    writeln!(&mut script, "}}").unwrap();
    writeln!(&mut script, "fast_refresh=1").unwrap();
    writeln!(&mut script, "slow_refresh=5").unwrap();
    writeln!(&mut script, "warmup_rounds=10").unwrap();
    writeln!(&mut script, "refresh_allowlist || true").unwrap();
    writeln!(
        &mut script,
        "while true; do refresh_allowlist || true; if [ \"$warmup_rounds\" -gt 0 ]; then \
         warmup_rounds=$((warmup_rounds-1)); sleep \"$fast_refresh\"; else sleep \
         \"$slow_refresh\"; fi; done &"
    )
    .unwrap();

    // Start local TCP proxies for slots.
    if let Some(ps) = proxies {
        // Stable ordering
        let mut ps = ps.clone();
        ps.sort_by_key(|p| p.local_port);

        for p in ps {
            // socat forwards raw TCP; higher-level schemes are handled by the program.
            writeln!(
                &mut script,
                "socat TCP-LISTEN:{},fork,reuseaddr,bind=127.0.0.1 TCP:{}:{} &",
                p.local_port, p.remote_host, p.remote_port
            )
            .unwrap();
        }
    }

    // Keep the sidecar alive; program shares this netns.
    writeln!(&mut script, "exec tail -f /dev/null").unwrap();

    script
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
